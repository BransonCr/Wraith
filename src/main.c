// Wraith's driver, the "ui" process: parse the arguments, get a stopped tracee
// by one of the two paths, then read commands until the tracee is gone.
//
// The no-libraries rule: libc is the C runtime and nothing more. If it ships
// with the kernel or libc it is fair game; anything that would need a package
// manager gets hand rolled, because that is the point of the project.
#include <assert.h>
#include <errno.h>
#include <limits.h>     // INT_MAX
#include <stdbool.h>
#include <stdio.h>      // printf, fgets, fprintf, perror
#include <stdlib.h>     // strtol
#include <string.h>     // strcmp, strncmp, strlen, strcspn, strsignal

#include <sys/types.h>  // pid_t
#include <sys/user.h>   // struct user_regs_struct
#include <inttypes.h>
#include <process.h>    // launch | attach | resume | wait | registers | detach
#include <registers.h>
// One command line. Larger than any command Wraith will ever take, and fixed,
// so the front end allocates nothing at all (3.1).
enum {
    WRAITH_MAIN_COMMAND_LENGTH_MAX = 256,
    WRAITH_MAIN_WORDS_MAX = 4,
};
static int target_open(int argc, char **argv, struct process *out);
static pid_t pid_parse(const char *text);
static bool command_read(char *buffer, size_t buffer_size);
static void command_handle(struct process *p, char *command);
static uint32_t command_split(char *command, char *words[], uint32_t words_max);
static void command_register(struct process *p, char *const words[], uint32_t count);
static void registers_print_all(struct process *p);
static void register_print_one(struct process *p, const char *name);
static void register_set_one(struct process *p, const char *name, const char *text);
static bool value_parse(const char *text, uint64_t *out);
static void stop_print(const struct process *p, struct stop_reason reason);
static bool prefix_match(const char *text, const char *full);
int main(int argc, char **argv) {
    assert(argc >= 1);
    assert(argv != NULL);

    struct process proc;
    if (target_open(argc, argv, &proc) == -1) return 1;
    assert(proc.state == PROC_STOPPED);

    char command[WRAITH_MAIN_COMMAND_LENGTH_MAX];
    while (command_read(command, sizeof command)) {
        command_handle(&proc, command);
        if (process_gone(&proc)) break;           // Nothing left to debug.
    }

    if (process_detach(&proc) == -1) return 1;
    return 0;
}

// wraith <program>  launches it under trace.
// wraith -p <pid>   attaches to a process already running.
// Both paths must reach the same place: a stopped tracee with a known pid.
static int target_open(int argc, char **argv, struct process *out) {
    assert(argv != NULL);
    assert(out != NULL);

    if (argc == 2) return process_launch(argv[1], out);

    if (argc == 3) {
        if (strcmp(argv[1], "-p") == 0) {
            const pid_t pid = pid_parse(argv[2]);
            if (pid > 0) return process_attach(pid, out);
            fprintf(stderr, "not a pid: %s\n", argv[2]);
            return -1;
        }
    }

    fprintf(stderr, "usage: %s <program> | -p <pid>\n", argv[0]);
    return -1;
}

// Parses a decimal pid, returning 0 for anything that is not one. 0 is a safe
// failure value because it is never a process we could trace, and strtol alone
// is not enough: it reports "banana" as 0 through the return value, which is
// indistinguishable from success without checking where it stopped.
static pid_t pid_parse(const char *text) {
    assert(text != NULL);

    char *end = NULL;
    errno = 0;
    const long value = strtol(text, &end, 10);

    if (errno != 0) return 0;      // Out of range for a long.
    if (end == text) return 0;     // No digits at all.
    if (*end != '\0') return 0;    // Trailing junk, e.g. "12x".
    if (value <= 0) return 0;
    if (value > INT_MAX) return 0; // Out of range for a pid_t.
    return (pid_t)value;
}

// Prompts and reads one line, with the newline stripped. Returns false at EOF,
// which is how ctrl-D ends the session.
static bool command_read(char *buffer, size_t buffer_size) {
    assert(buffer != NULL);
    assert(buffer_size > 1);

    printf("wraith> ");
    if (fflush(stdout) == EOF) {
        perror("fflush");
        return false;
    }
    if (fgets(buffer, (int)buffer_size, stdin) == NULL) {
        printf("\n");  // Leave the shell prompt on a line of its own.
        return false;
    }
    buffer[strcspn(buffer, "\n")] = '\0';
    return true;
}

// All of the front end's branching lives here, so the leaves below stay
// straight-line code: push the ifs up, keep the helpers pure.
static void command_handle(struct process *p, char *command) {
    assert(p != NULL);
    assert(command != NULL);

    char *words[WRAITH_MAIN_WORDS_MAX];
    const uint32_t count = command_split(command, words, WRAITH_MAIN_WORDS_MAX);
    if (count == 0) return;  // A bare enter is not an error.

    if (prefix_match(words[0], "continue")) {
        if (process_resume(p) == -1) return;
        const struct stop_reason reason = process_wait(p);
        stop_print(p, reason);
        return;
    }
    if (prefix_match(words[0], "register")) {
        command_register(p, words, count);
        return;
    }
    if (prefix_match(words[0], "exit")) {
        process_detach(p);
        return;
    }
    fprintf(stderr, "unknown command: %s\n", words[0]);
}

// rip: the instruction pointer, the address of the next instruction. This is
//      "where the process is" at the moment we froze it.
// rsp: the stack pointer, the top of the stack (it grows downward on x86-64).
// rbp: the frame pointer, the bottom of the current call frame. rsp..rbp is
//      this function's frame, so rbp is what a backtrace walks. Garbage under
//      -fomit-frame-pointer, which is one reason we never build with it.
// rax: general purpose, by convention the return value or the syscall number.

static void stop_print(const struct process *p, struct stop_reason reason) {
    assert(p != NULL);
    assert(reason.reason != PROC_RUNNING);

    printf("process %d ", p->pid);
    switch (reason.reason) {
        case PROC_EXITED:     printf("exited with status %u\n", reason.info); break;
        case PROC_TERMINATED: printf("terminated: %s\n", strsignal(reason.info)); break;
        case PROC_STOPPED:    printf("stopped: %s\n", strsignal(reason.info)); break;
        // A running process is not a stop reason, and a value outside the enum
        // is a bug in us, not in the tracee. Adding a state fails loudly here.
        default: assert(false); break;
    }
}

// True when text is a non-empty prefix of full, so "c" and "cont" both mean
// "continue". bool, not int: the return type should say what the value means.
static bool prefix_match(const char *text, const char *full) {
    assert(text != NULL);
    assert(full != NULL);

    const size_t text_length = strlen(text);
    if (text_length == 0) return false;
    if (text_length > strlen(full)) return false;
    return strncmp(text, full, text_length) == 0;
}


static uint32_t command_split(char *command, char *words[], uint32_t words_max) {
    assert (command != NULL);
    assert (words != NULL);
    assert (words_max > 0);

    uint32_t count = 0;
    char *save = NULL;
    for (char *word = strtok_r(command, " \t", &save);
            word != NULL;
            word = strtok_r(NULL, " \t", &save))
    {
        if (count == words_max) break;
        words[count] = word;
        count++;
    }
    assert(count <= words_max);
    return count;
}

// register read            every register
// register read all        the same, said out loud
// register read <name>     one
// register write <name> <value>
static void command_register(struct process *p, char *const words[], uint32_t count) {
    assert(p != NULL);
    assert(words != NULL);
    assert(count >= 1);

    if (count >= 2) {
        if (prefix_match(words[1], "read")) {
            if (count == 2) {
                registers_print_all(p);
            } else {
                if (strcmp(words[2], "all") == 0) {
                    registers_print_all(p);
                } else {
                    register_print_one(p, words[2]);
                }
            }
            return;
        }
        if (prefix_match(words[1], "write")) {
            if (count >= 4) {
                register_set_one(p, words[2], words[3]);
                return;
            }
        }
    }
    fprintf(stderr, "usage: register read [all|<name>] | register write <name> <value>\n");
}
//
// One fetch, eighteen reads. 6.5 is what makes this free: the block came out of
// the kernel once when the tracee stopped, so dumping every register costs the
// same zero syscalls as dumping one.
static void registers_print_all(struct process *p) {
    assert(p != NULL);

    const struct user_regs_struct *const registers = process_registers(p);
    if (registers == NULL) return;

    for (uint32_t index = 0; index < WRAITH_REGISTER_COUNT; index++) {
        assert(register_table[index].name != NULL);

        struct register_value value;
        register_read(registers, &register_table[index], &value);
        printf("%-7s 0x%016" PRIx64 "\n", register_table[index].name, value.integer);
    }
}
static void register_print_one(struct process *p, const char *name) {
    assert(p != NULL);
    assert(name != NULL);

    const struct register_info *const info = register_by_name(name);
    if (info == NULL) {
        fprintf(stderr, "no such register: %s\n", name);
        return;
    }

    const struct user_regs_struct *const registers = process_registers(p);
    if (registers == NULL) return;

    struct register_value value;
    register_read(registers, info, &value);
    printf("%-7s 0x%016" PRIx64 "\n", info->name, value.integer);
}

static void register_set_one(struct process *p, const char *name, const char *text) {
    assert(p != NULL);
    assert(name != NULL);
    assert(text != NULL);

    const struct register_info *const info = register_by_name(name);
    if (info == NULL) {
        fprintf(stderr, "no such register: %s\n", name);
        return;
    }

    uint64_t value = 0;
    if (!value_parse(text, &value)) {
        fprintf(stderr, "not a number: %s\n", text);
        return;
    }

    const struct user_regs_struct *const current = process_registers(p);
    if (current == NULL) return;

    // Edit a copy and hand the whole block down, rather than reaching into the
    // cache: the ui layer states its intent as data and process owns when that
    // data crosses the kernel boundary.
    struct user_regs_struct block = *current;
    register_write(&block, info, value);
    if (process_registers_set(p, &block) == -1) return;

    printf("%-7s 0x%016" PRIx64 "\n", info->name, value);
}

// Base 0, so 0x1f, 037 and 31 all work the way the user expects from gdb.
// A typo must not silently become 0 and get written to rip, so every failure
// mode strtoull has is checked rather than folded into the return value.
static bool value_parse(const char *text, uint64_t *out) {
    assert(text != NULL);
    assert(out != NULL);

    char *end = NULL;
    errno = 0;
    const unsigned long long value = strtoull(text, &end, 0);

    if (errno != 0) return false;    // Out of range.
    if (end == text) return false;   // No digits at all.
    if (*end != '\0') return false;  // Trailing junk, e.g. "0x1fz".

    *out = (uint64_t)value;
    return true;
}
