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

#include <process.h>    // launch | attach | resume | wait | registers | detach

// One command line. Larger than any command Wraith will ever take, and fixed,
// so the front end allocates nothing at all (3.1).
enum {
    WRAITH_MAIN_COMMAND_LENGTH_MAX = 256,
};
static int target_open(int argc, char **argv, struct process *out);
static pid_t pid_parse(const char *text);
static bool command_read(char *buffer, size_t buffer_size);
static void command_handle(struct process *p, const char *command);
static void registers_print(struct process *p);
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
static void command_handle(struct process *p, const char *command) {
    assert(p != NULL);
    assert(command != NULL);

    if (command[0] == '\0') return;  // A bare enter is not an error.

    if (prefix_match(command, "continue")) {
        if (process_resume(p) == -1) return;
        const struct stop_reason reason = process_wait(p);
        stop_print(p, reason);
        return;
    }
    if (prefix_match(command, "register")) {
        registers_print(p);
        return;
    }
    if (prefix_match(command, "exit")) {
        process_detach(p);
        return;
    }
    fprintf(stderr, "unknown command: %s\n", command);
}

// rip: the instruction pointer, the address of the next instruction. This is
//      "where the process is" at the moment we froze it.
// rsp: the stack pointer, the top of the stack (it grows downward on x86-64).
// rbp: the frame pointer, the bottom of the current call frame. rsp..rbp is
//      this function's frame, so rbp is what a backtrace walks. Garbage under
//      -fomit-frame-pointer, which is one reason we never build with it.
// rax: general purpose, by convention the return value or the syscall number.
static void registers_print(struct process *p) {
    assert(p != NULL);

    // No ptrace call here: the block was fetched once when the tracee stopped.
    const struct user_regs_struct *const registers = process_registers(p);
    if (registers == NULL) return;

    printf("rip = 0x%llx\n", registers->rip);
    printf("rsp = 0x%llx\n", registers->rsp);
    printf("rbp = 0x%llx\n", registers->rbp);
    printf("rax = 0x%llx\n", registers->rax);
}

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
