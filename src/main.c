// Wraith's driver, the "ui" layer: parse the arguments, get a stopped tracee by
// one of the two paths, then read commands until the tracee is gone.
//
// This is the only layer that prints and the only layer that knows what a
// command line looks like. Everything below it speaks in structs. It is also
// the only layer that holds both the process and the breakpoint table, which is
// why every control_* call in the program starts here.
#include <assert.h>
#include <errno.h>
#include <inttypes.h>   // PRIx64
#include <limits.h>     // INT_MAX
#include <stdbool.h>
#include <stdio.h>      // printf, fgets, fprintf, perror
#include <stdlib.h>     // strtol, strtoul, strtoull
#include <string.h>     // strcmp, strncmp, strlen, strcspn, strsignal

#include <sys/types.h>  // pid_t
#include <sys/user.h>   // struct user_regs_struct

#include <control.h>
#include <disassembler.h>
#include <process.h>
#include <registers.h>

enum {
    main_command_length_bytes_max = 256,

    main_words_max = 8,

    main_memory_bytes_max = 1024,
    main_memory_bytes_default = 32,
    main_memory_bytes_per_line = 16,  // What objdump and gdb both use.
    main_write_bytes_max = 64,

    main_disassemble_count_max = 64,
    main_disassemble_count_default = 5,
};

static int target_open(int argc, char **argv, struct process *out);
static pid_t pid_parse(const char *text);
static bool command_read(char *buffer, size_t buffer_size);
static void command_handle(struct control *c, struct process *p, char *command);
static uint32_t command_split(char *command, char *words[], uint32_t words_max);
static bool prefix_match(const char *text, const char *full);
static bool prefix_match_least(const char *text, const char *full, size_t length_least);

static void command_help(char *const words[], uint32_t count);
static void help_all(void);
static void help_breakpoint(void);
static void help_disassemble(void);
static void help_memory(void);
static void help_register(void);

static void command_breakpoint(struct control *c, struct process *p, char *const words[],
                               uint32_t count);
static void breakpoints_print(const struct control *c);

static void command_memory(struct control *c, struct process *p, char *const words[],
                           uint32_t count);
static void memory_print(const struct control *c, struct process *p, uint64_t address,
                         uint32_t size_bytes);
static void memory_patch(struct control *c, struct process *p, uint64_t address,
                         const char *text);
static uint32_t bytes_parse(const char *text, uint8_t *out, uint32_t count_max);

static void command_disassemble(struct control *c, struct process *p, char *const words[],
                                uint32_t count);
static void disassembly_print(const struct control *c, struct process *p, uint64_t address,
                              uint32_t instructions_count);

static void command_register(struct process *p, char *const words[], uint32_t count);
static void registers_print_all(struct process *p);
static void register_print_one(struct process *p, const char *name);
static void register_set_one(struct process *p, const char *name, const char *text);

static void stop_print(struct process *p, struct stop_reason reason);
static bool value_parse(const char *text, uint64_t *out);
int main(int argc, char **argv) {
    assert(argc >= 1);
    assert(argv != NULL);

    struct process proc;
    if (target_open(argc, argv, &proc) == -1) return 1;
    assert(proc.state == PROC_STOPPED);

    struct control ctl;
    control_init(&ctl);

    printf("process: %d\n", proc.pid);
    const struct user_regs_struct *const registers = process_registers(&proc);
    if (registers != NULL) {
        printf("stopped at 0x%016" PRIx64 "\n", (uint64_t)registers->rip);
    }

    char command[main_command_length_bytes_max];
    while (command_read(command, sizeof command)) {
        command_handle(&ctl, &proc, command);
        if (process_gone(&proc)) break;  // Nothing left to debug.
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

    if (errno != 0) return 0;       // Out of range for a long.
    if (end == text) return 0;      // No digits at all.
    if (*end != '\0') return 0;     // Trailing junk, e.g. "12x".
    if (value <= 0) return 0;
    if (value > INT_MAX) return 0;  // Out of range for a pid_t.
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

// alphabetical ordejj
static void command_handle(struct control *c, struct process *p, char *command) {
    assert(c != NULL);
    assert(p != NULL);
    assert(command != NULL);

    char *words[main_words_max];
    const uint32_t count = command_split(command, words, main_words_max);
    if (count == 0) return;  // A bare enter is not an error.
    if (count > main_words_max) {
        fprintf(stderr, "too many arguments (%d max)\n", main_words_max);
        return;
    }

    if (prefix_match(words[0], "breakpoint")) {
        command_breakpoint(c, p, words, count);
        return;
    }
    if (prefix_match(words[0], "continue")) {
        struct stop_reason reason;
        // control_continue, not process_resume: rip may be sitting on one of
        // our own 0xCC bytes, and continuing without stepping over it traps at
        // the same address forever.
        if (control_continue(c, p, &reason) == -1) return;
        stop_print(p, reason);
        return;
    }
    if (prefix_match(words[0], "disassemble")) {
        command_disassemble(c, p, words, count);
        return;
    }
    if (prefix_match(words[0], "exit")) {
        process_detach(p);
        return;
    }
    if (prefix_match(words[0], "help") || prefix_match(words[0], "h")) {
        command_help(words, count);
        return;
    }
    if (prefix_match(words[0], "memory")) {
        command_memory(c, p, words, count);
        return;
    }
    if (prefix_match(words[0], "register")) {
        command_register(p, words, count);
        return;
    }
    if (prefix_match(words[0], "step")) {
        struct stop_reason reason;
        if (control_step(c, p, &reason) == -1) return;
        stop_print(p, reason);
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

static void stop_print(struct process *p, struct stop_reason reason) {
    assert(p != NULL);
    assert(reason.reason != PROC_RUNNING);

    printf("process %d ", p->pid);
    switch (reason.reason) {
        case PROC_EXITED:
            printf("exited with status %u\n", reason.info);
            break;
        case PROC_TERMINATED:
            printf("terminated: %s\n", strsignal(reason.info));
            break;
        case PROC_STOPPED: {
            // The address matters more than the signal name: it is what you
            // feed back into breakpoint set and disassemble -a.
            const struct user_regs_struct *const registers = process_registers(p);
            if (registers == NULL) {
                printf("stopped: %s\n", strsignal(reason.info));
            } else {
                printf("stopped: %s at 0x%016" PRIx64 "\n", strsignal(reason.info),
                       (uint64_t)registers->rip);
            }
            break;
        }
        // A running process is not a stop reason, and a value outside the enum
        // is a bug in us, not in the tracee. Adding a state fails loudly here.
        default:
            assert(false);
            break;
    }
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
       if (count < words_max) words[count] = word;
       count++;
    }
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

static bool prefix_match(const char *text, const char *full) {
    assert(text != NULL);
    assert(full != NULL);

    const size_t text_length = strlen(text);
    if (text_length == 0) return false;
    if (text_length > strlen(full)) return false;
    return strncmp(text, full, text_length) == 0;
}

//
// Prefix matching with a floor, for subcommands that share a first letter.
// "disable" and "delete" both start with "d", and a plain prefix match would
// hand "d" to whichever the dispatch happens to test first — silently deleting
// a breakpoint the user meant to keep. Three characters disambiguates them, so
// both demand three and a bare "d" falls through to the usage line.
static bool prefix_match_least(const char *text, const char *full, size_t length_least) {
    assert(text != NULL);
    assert(full != NULL);
    assert(length_least > 0);

    if (strlen(text) < length_least) return false;
    return prefix_match(text, full);
}

static void command_help(char *const words[], uint32_t count) {
    assert(words != NULL);
    assert(count >= 1);

    if (count == 1) {
        help_all();
        return;
    }
    if (prefix_match(words[1], "breakpoint")) {
        help_breakpoint();
        return;
    }
    if (prefix_match(words[1], "disassemble")) {
        help_disassemble();
        return;
    }
    if (prefix_match(words[1], "memory")) {
        help_memory();
        return;
    }
    if (prefix_match(words[1], "register")) {
        help_register();
        return;
    }
    fprintf(stderr, "no help available on that\n");
}

static void help_all(void) {
    printf("breakpoint   set, list, enable, disable or delete a breakpoint\n");
    printf("continue     resume the process\n");
    printf("disassemble  decode machine code into assembly\n");
    printf("exit         detach and leave\n");
    printf("help         this list, or help <command>\n");
    printf("memory       read or write the process's memory\n");
    printf("register     read or write the process's registers\n");
    printf("step         execute exactly one instruction\n");
}

static void help_breakpoint(void) {
    printf("breakpoint list\n");
    printf("breakpoint set <address>\n");
    printf("breakpoint enable <id>\n");
    printf("breakpoint disable <id>\n");
    printf("breakpoint delete <id>\n");
}

static void help_disassemble(void) {
    printf("disassemble              %d instructions at rip\n", main_disassemble_count_default);
    printf("disassemble -c <count>   count instructions, 1 to %d\n", main_disassemble_count_max);
    printf("disassemble -a <address> start somewhere other than rip\n");
}

static void help_memory(void) {
    printf("memory read <address>\n");
    printf("memory read <address> <count>\n");
    printf("memory write <address> [0xff,0xde,0xad]\n");
}

static void help_register(void) {
    printf("register read\n");
    printf("register read all\n");
    printf("register read <name>\n");
    printf("register write <name> <value>\n");
}

static void command_breakpoint(struct control *c, struct process *p, char *const words[],
                               uint32_t count) {
    assert(c != NULL);
    assert(p != NULL);
    assert(words != NULL);
    assert(count >= 1);

    if (count == 2) {
        if (prefix_match(words[1], "list")) {
            breakpoints_print(c);
            return;
        }
    }

    if (count == 3) {
        if (prefix_match(words[1], "set")) {
            uint64_t address = 0;
            if (!value_parse(words[2], &address)) {
                fprintf(stderr, "not an address: %s\n", words[2]);
                return;
            }
            uint32_t id = 0;
            if (control_breakpoint_set(c, p, address, &id) == -1) return;
            printf("breakpoint %u set at 0x%016" PRIx64 "\n", id, address);
            return;
        }

        uint64_t id = 0;
        if (!value_parse(words[2], &id)) {
            fprintf(stderr, "not a breakpoint id: %s\n", words[2]);
            return;
        }
        if (id > UINT32_MAX) {
            fprintf(stderr, "no breakpoint with id %s\n", words[2]);
            return;
        }

        if (prefix_match(words[1], "enable")) {
            control_breakpoint_enable(c, p, (uint32_t)id);
            return;
        }
        if (prefix_match_least(words[1], "disable", 3)) {
            control_breakpoint_disable(c, p, (uint32_t)id);
            return;
        }
        if (prefix_match_least(words[1], "delete", 3)) {
            control_breakpoint_delete(c, p, (uint32_t)id);
            return;
        }
    }
    help_breakpoint();
}

static void breakpoints_print(const struct control *c) {
    assert(c != NULL);

    const uint32_t count = control_breakpoints_count(c);
    if (count == 0) {
        printf("no breakpoints set\n");
        return;
    }

    for (uint32_t index = 0; index < count; index++) {
        const struct control_breakpoint *const breakpoint = control_breakpoint_at(c, index);
        assert(breakpoint != NULL);
        printf("%u: 0x%016" PRIx64 " %s\n", breakpoint->id, breakpoint->address,
               breakpoint->enabled ? "enabled" : "disabled");
    }
}
// memory read <address>
// memory read <address> <count>
// memory write <address> [0xff,0xde,0xad]
static void command_memory(struct control *c, struct process *p, char *const words[],
                           uint32_t count) {
    assert(c != NULL);
    assert(p != NULL);
    assert(words != NULL);
    assert(count >= 1);

    if (count >= 3) {
        uint64_t address = 0;
        if (!value_parse(words[2], &address)) {
            fprintf(stderr, "not an address: %s\n", words[2]);
            return;
        }

        if (prefix_match(words[1], "read")) {
            uint64_t size_bytes = main_memory_bytes_default;
            if (count == 4) {
                if (!value_parse(words[3], &size_bytes)) {
                    fprintf(stderr, "not a byte count: %s\n", words[3]);
                    return;
                }
            }
            if (size_bytes == 0) {
                fprintf(stderr, "byte count must be at least 1\n");
                return;
            }
            if (size_bytes > main_memory_bytes_max) {
                fprintf(stderr, "byte count must be at most %d\n", main_memory_bytes_max);
                return;
            }
            memory_print(c, p, address, (uint32_t)size_bytes);
            return;
        }

        if (count == 4) {
            if (prefix_match(words[1], "write")) {
                memory_patch(c, p, address, words[3]);
                return;
            }
        }
    }
    help_memory();
}

static void memory_print(const struct control *c, struct process *p, uint64_t address,
                         uint32_t size_bytes) {
    assert(c != NULL);
    assert(p != NULL);
    assert(size_bytes > 0);
    assert(size_bytes <= main_memory_bytes_max);

    // Through control, never through process: a raw read shows wraith's own
    // 0xCC wherever a breakpoint is armed, and the user did not put it there.
    uint8_t bytes[main_memory_bytes_max];
    const int64_t moved = control_memory_read(c, p, address, bytes, size_bytes);
    if (moved <= 0) {
        fprintf(stderr, "could not read %u bytes at 0x%016" PRIx64 "\n", size_bytes, address);
        return;
    }
    assert(moved <= (int64_t)size_bytes);

    // A short read is normal at the end of a mapping, so print what arrived
    // rather than what was asked for.
    const uint32_t moved_bytes = (uint32_t)moved;
    for (uint32_t offset = 0; offset < moved_bytes; offset += main_memory_bytes_per_line) {
        printf("0x%016" PRIx64 ":", address + offset);
        for (uint32_t column = 0; column < main_memory_bytes_per_line; column++) {
            if (offset + column >= moved_bytes) break;
            printf(" %02x", bytes[offset + column]);
        }
        printf("\n");
    }
}

static void memory_patch(struct control *c, struct process *p, uint64_t address,
                         const char *text) {
    assert(c != NULL);
    assert(p != NULL);
    assert(text != NULL);

    uint8_t bytes[main_write_bytes_max];
    const uint32_t count = bytes_parse(text, bytes, main_write_bytes_max);
    if (count == 0) {
        fprintf(stderr, "expected bytes like [0xff,0xde,0xad], got: %s\n", text);
        return;
    }

    // Through control, so a write landing on an armed breakpoint updates the
    // saved byte instead of erasing the trap that makes it work.
    if (control_memory_write(c, p, address, bytes, count) == -1) return;
    printf("wrote %u byte%s at 0x%016" PRIx64 "\n", count, count == 1 ? "" : "s", address);
}

// Parses "[0xff,0xde,0xad]" into bytes, returning the count. Returns 0 for
// anything malformed, which is a safe failure value because a zero-byte write
// is meaningless and so can never be a legitimate answer.
//
// Base 0, so [0xff], [255] and [0377] all work, matching value_parse rather
// than inventing a second numeric dialect for the same debugger.
static uint32_t bytes_parse(const char *text, uint8_t *out, uint32_t count_max) {
    assert(text != NULL);
    assert(out != NULL);
    assert(count_max > 0);

    if (text[0] != '[') return 0;

    const char *cursor = text + 1;
    uint32_t count = 0;

    // Bounded (5.6): one byte per pass, so count_max passes is a ceiling no
    // well-formed input can reach.
    for (uint32_t pass = 0; pass < count_max; pass++) {
        char *end = NULL;
        errno = 0;
        const unsigned long value = strtoul(cursor, &end, 0);

        if (errno != 0) return 0;
        if (end == cursor) return 0;  // Not a number at all, e.g. "[]" or "[,".
        if (value > 0xFF) return 0;   // Not a byte.

        out[count] = (uint8_t)value;
        count++;
        cursor = end;

        if (*cursor == ']') break;
        if (*cursor != ',') return 0;
        cursor++;
    }

    if (*cursor != ']') return 0;    // More bytes than count_max.
    if (cursor[1] != '\0') return 0; // Trailing junk after the bracket.

    assert(count > 0);
    assert(count <= count_max);
    return count;
}

// disassemble
// disassemble -c <count>
// disassemble -a <address>
// disassemble -c <count> -a <address>
static void command_disassemble(struct control *c, struct process *p, char *const words[],
                                uint32_t count) {
    assert(c != NULL);
    assert(p != NULL);
    assert(words != NULL);
    assert(count >= 1);

    uint64_t address = 0;
    uint32_t instructions_count = main_disassemble_count_default;
    bool address_given = false;

    // Flags come in pairs, so step two at a time. Bounded by the word count,
    // which command_handle has already capped at main_words_max.
    for (uint32_t index = 1; index < count; index += 2) {
        if (index + 1 == count) {  // A flag with no value after it.
            help_disassemble();
            return;
        }
        if (strcmp(words[index], "-a") == 0) {
            if (!value_parse(words[index + 1], &address)) {
                fprintf(stderr, "not an address: %s\n", words[index + 1]);
                return;
            }
            address_given = true;
        } else {
            if (strcmp(words[index], "-c") == 0) {
                uint64_t value = 0;
                if (!value_parse(words[index + 1], &value)) {
                    fprintf(stderr, "not a count: %s\n", words[index + 1]);
                    return;
                }
                if (value == 0) {
                    fprintf(stderr, "count must be at least 1\n");
                    return;
                }
                if (value > main_disassemble_count_max) {
                    fprintf(stderr, "count must be at most %d\n", main_disassemble_count_max);
                    return;
                }
                instructions_count = (uint32_t)value;
            } else {
                help_disassemble();
                return;
            }
        }
    }

    // rip is the default because it is the one address guaranteed to be an
    // instruction boundary. x86-64 instructions are variable length, so
    // starting anywhere else is the caller promising they know what they are
    // pointing at.
    if (!address_given) {
        const struct user_regs_struct *const registers = process_registers(p);
        if (registers == NULL) return;
        address = registers->rip;
    }

    disassembly_print(c, p, address, instructions_count);
}

static void disassembly_print(const struct control *c, struct process *p, uint64_t address,
                              uint32_t instructions_count) {
    assert(c != NULL);
    assert(p != NULL);
    assert(instructions_count > 0);
    assert(instructions_count <= main_disassemble_count_max);

    // 15 bytes per instruction is the architectural maximum, so this is the
    // smallest request that cannot run out of input before the decoder has
    // produced the instructions asked for. It over-reads most of the time, and
    // that costs nothing: it is one syscall either way.
    uint8_t bytes[main_disassemble_count_max * disassembler_instruction_size_bytes_max];
    const uint32_t size_bytes = instructions_count * disassembler_instruction_size_bytes_max;

    // The single most important call in this file. control_memory_read paints
    // saved original bytes back over every armed breakpoint; process_memory_read
    // does not. Read raw and every breakpoint in range decodes as int3, which is
    // wraith's byte, not the program's.
    const int64_t moved = control_memory_read(c, p, address, bytes, size_bytes);
    if (moved <= 0) {
        fprintf(stderr, "could not read code at 0x%016" PRIx64 "\n", address);
        return;
    }
    assert(moved <= (int64_t)size_bytes);

    struct disassembler_instruction instructions[main_disassemble_count_max];
    const uint32_t decoded =
        disassembler_decode(bytes, (uint32_t)moved, address, instructions, instructions_count);
    if (decoded == 0) {
        fprintf(stderr, "no instruction decoded at 0x%016" PRIx64 "\n", address);
        return;
    }
    assert(decoded <= instructions_count);

    for (uint32_t index = 0; index < decoded; index++) {
        printf("0x%016" PRIx64 ": %s\n", instructions[index].address, instructions[index].text);
    }
}

// register read            every register
// register read all        the same, said out loud
// register read <name>     one
// register write <name> <value>

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
