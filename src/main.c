// Wraith's driver, the "ui" layer: parse the arguments, get a stopped tracee by
// one of the two paths, then read commands until the tracee is gone.
//
// This is the only layer that prints and the only layer that knows what a
// command line looks like. Everything below it speaks in structs. It is also
// the only layer that holds both the process and the breakpoint table, which is
// why every control_* call in the program starts here.
#include <signal.h>     // SIGTRAP
#include <assert.h>
#include <errno.h>
#include <inttypes.h>   // PRIx64
#include <limits.h>     // INT_MAX
#include <stdbool.h>
#include <stdio.h>      // printf, fgets, fprintf, perror
#include <stdlib.h>     // strtol, strtoul, strtoull
#include <string.h>     // strcmp, strncmp, strlen, strcspn, strsignal
#include <ctype.h>      // isspace

#include <sys/types.h>  // pid_t
#include <sys/user.h>   // struct user_regs_struct

#include <control/control.h>
#include <disassembler/disassembler.h>
#include <process/process.h>
#include <registers/registers.h>
#include <syscall/syscall.h>
#include <elf/elf.h>
#include <dwarf/dwarf.h>
#include <arena/arena.h>


enum {
    main_command_length_bytes_max = 256,
    main_dwarf_arena_bytes = 256u * 1024u * 1024u,  // 256 MiB.

    main_syscall_name_bytes_max = 32,
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
static void command_handle(struct control *c, struct process *p, const struct elf *elf,
                           struct dwarf *dwarf, uint64_t load_bias, char *command);
static void command_function(const struct elf *elf, struct dwarf *dwarf, uint64_t load_bias,
                             char *const words[], uint32_t count);
static void help_function(void);
static uint32_t command_split(char *command, char *words[], uint32_t words_max);
static bool prefix_match(const char *text, const char *full);
static bool prefix_match_least(const char *text, const char *full, size_t length_least);
static void command_catchpoint(struct control *c, char *const words[], uint32_t count);
static void help_catchpoint(void);
static void stop_print_trap(struct process *p, struct stop_reason reason);
static uint32_t syscalls_parse(const char *text, uint16_t *out, uint32_t count_max);
static bool syscalls_parse_one(const char *token, size_t length, uint16_t *out);

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

static void stop_print(struct process *p, const struct elf *elf, uint64_t load_bias,
                       struct stop_reason reason);
static bool value_parse(const char *text, uint64_t *out);


static bool symbols_open(struct process *p, struct elf *elf, uint64_t *load_bias_out);
static void symbol_print_at(const struct elf *elf, uint64_t load_bias, uint64_t address);
static void command_symbol(const struct elf *elf, uint64_t load_bias, char *const words[],
                           uint32_t count);
static void help_symbol(void);

static volatile sig_atomic_t interrupt_at_prompt = 0;
static volatile sig_atomic_t interrupt_pid = 0;

static_assert(sizeof(pid_t) <= sizeof(sig_atomic_t),
              "a pid must survive the round trip through the handler's type");
static void interrupt_handler(int signal_number) {
    (void)signal_number;

    const int errno_saved = errno;

    if (interrupt_at_prompt == 0) {
        if (interrupt_pid > 0) {
            (void)kill((pid_t)interrupt_pid, SIGSTOP);
        }
    }

    errno = errno_saved;
}

static int interrupt_install(pid_t pid) {
    assert(pid > 0);
    assert(interrupt_pid == 0);  // Installed once, at startup, never replaced.

    interrupt_pid = pid;

    struct sigaction action = {
        .sa_handler = interrupt_handler,
        .sa_flags = 0,
    };
    if (sigemptyset(&action.sa_mask) == -1) {
        perror("sigemptyset");
        return -1;
    }
    if (sigaction(SIGINT, &action, NULL) == -1) {
        perror("sigaction");
        return -1;
    }
    return 0;
}
//
// Maps the tracee's own executable and works out the one constant relating its
// link-time addresses to the addresses the process is actually running at.
static bool symbols_open(struct process *p, struct elf *elf, uint64_t *load_bias_out) {
    assert(p != NULL);
    assert(elf != NULL);
    assert(load_bias_out != NULL);

    char path[64];
    if (!process_executable_path(p, path, sizeof path)) return false;
    if (elf_open(path, elf) == -1) return false;

    // After the exec, never before. /proc/<pid>/auxv is readable either way,
    // and before the exec it still describes wraith's own image — so a bias
    // taken there is wrong, and looks entirely plausible.
    uint64_t entry_virtual = 0;
    if (!process_auxv(p, AT_ENTRY, &entry_virtual)) {
        elf_close(elf);
        return false;
    }

    const uint64_t entry_file = elf_entry(elf);
    if (entry_virtual < entry_file) {
        fprintf(stderr, "entry 0x%" PRIx64 " is below the file's 0x%" PRIx64 "\n",
                entry_virtual, entry_file);
        elf_close(elf);
        return false;
    }

    *load_bias_out = entry_virtual - entry_file;
    return true;
}

int main(int argc, char **argv) {
    assert(argc >= 1);
    assert(argv != NULL);
    struct process proc;
    if (target_open(argc, argv, &proc) == -1) return 1;
    assert(proc.state == PROC_STOPPED);

    if (interrupt_install(proc.pid) == -1) return 1;

    struct control ctl;
    control_init(&ctl);

    struct elf elf;
    uint64_t load_bias = 0;
    const bool symbols = symbols_open(&proc, &elf, &load_bias);
    if (!symbols) fprintf(stderr, "no symbols: addresses only\n");

    // The arena outlives every dwarf query, so it is created here and passed
    // down. dwarf never owns it: the caller decides the lifetime and the ceiling.
    struct arena dwarf_arena = {0};
    struct dwarf dwarf = {0};
    bool debug_info = false;
    if (symbols) {
        if (arena_init(&dwarf_arena, main_dwarf_arena_bytes) == 0) {
            if (dwarf_open(&dwarf, &elf, &dwarf_arena) == 0) debug_info = dwarf_has_info(&dwarf);
        }
        if (!debug_info) fprintf(stderr, "no debug info: build with -g for `function`\n");
    }

    printf("process: %d\n", proc.pid);
    const struct user_regs_struct *const registers = process_registers(&proc);
    if (registers != NULL) {
        printf("stopped at 0x%016" PRIx64 "\n", (uint64_t)registers->rip);
    }

    char command[main_command_length_bytes_max];
    while (command_read(command, sizeof command)) {
        command_handle(&ctl, &proc, symbols ? &elf : NULL, debug_info ? &dwarf : NULL,
                       load_bias, command);
        if (process_gone(&proc)) break;
    }

    arena_deinit(&dwarf_arena);
    if (symbols) elf_close(&elf);
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

    // Bounded (5.6): one interrupt per pass. Someone leaning on ctrl-C is a
    // broken world, not a slow one.
    enum { interrupts_max = 64 };
    for (uint32_t attempt = 0; attempt < interrupts_max; attempt++) {
        printf("wraith> ");
        if (fflush(stdout) == EOF) {
            perror("fflush");
            return false;
        }

        // The window in which ctrl-C means the line rather than the tracee.
        interrupt_at_prompt = 1;
        errno = 0;
        char *const line = fgets(buffer, (int)buffer_size, stdin);
        interrupt_at_prompt = 0;

        if (line != NULL) {
            buffer[strcspn(buffer, "\n")] = '\0';
            return true;
        }

        if (feof(stdin)) {
            printf("\n");  // Leave the shell prompt on a line of its own.
            return false;
        }
        if (errno != EINTR) {
            perror("fgets");
            return false;
        }
        printf("\n");
        clearerr(stdin);
    }

    fprintf(stderr, "interrupted too many times\n");
    return false;
}
// alphabetical ordejj
static void command_handle(struct control *c, struct process *p, const struct elf *elf,
                           struct dwarf *dwarf, uint64_t load_bias, char *command){
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
    if(prefix_match_least(words[0], "catchpoint", 2)) {
        command_catchpoint(c, words, count);
        return;
    }
    if (prefix_match(words[0], "continue")) {
        struct stop_reason reason;
        if (control_continue(c, p, &reason) == -1) return;
        stop_print(p, elf, load_bias, reason);
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
    if (prefix_match_least(words[0], "step", 2)) {
        struct stop_reason reason;
        if (control_step(c, p, &reason) == -1) return;
        stop_print(p, elf, load_bias, reason);
        return;
    }
    if (prefix_match_least(words[0], "symbol", 2)) {
        if (elf == NULL) {
            fprintf(stderr, "no symbols for this process\n");
            return;
        }
        command_symbol(elf, load_bias, words, count);
        return;
    }
    if (prefix_match_least(words[0], "function", 2)) {
        if(dwarf == NULL) {
            fprintf(stderr, "no debug info for this process\n");
            return;
        }
        assert(elf != NULL);
        command_function(elf, dwarf, load_bias, words, count);
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

static void stop_print(struct process *p, const struct elf *elf, uint64_t load_bias,
                       struct stop_reason reason) {
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
            const struct user_regs_struct *const registers = process_registers(p);
            if (registers == NULL) {
                printf("stopped: %s\n", strsignal(reason.info));
            } else {
                printf("stopped: %s at 0x%016" PRIx64, strsignal(reason.info),
                       (uint64_t)registers->rip);
                symbol_print_at(elf, load_bias, (uint64_t)registers->rip);
                printf("\n");
            }
            stop_print_trap(p, reason);
            break;
        }
        // A running process is not a stop reason, and a value outside the enum
        // is a bug in us, not in the tracee. Adding a state fails loudly here.
        default:
            assert(false);
            break;
    }
}
// The second line of a stop, when there is one to say. Kept out of stop_print
// so that function stays a switch over the lifecycle and nothing else.
static void stop_print_trap(struct process *p, struct stop_reason reason) {
    assert(p != NULL);
    assert(reason.reason == PROC_STOPPED);

    if (reason.trap != PROC_TRAP_SYSCALL) return;

    const struct process_syscall *const syscall = process_syscall(p);
    if (syscall == NULL) return;

    const char *const name = syscall_name(syscall->number);
    if (syscall->entry) {
        printf("  syscall entry %s(%u)", name != NULL ? name : "syscall",
               syscall->number);

        for (uint32_t i = 0; i < process_syscall_max_arguments; i++) {
            printf(" 0x%" PRIx64, syscall->arguments[i]);
        }
        printf("\n");
        return;
    }

    // is_error comes from the kernel rather than from the sign of the return
    // value, because a negative return is ambiguous: mmap legitimately returns
    // addresses whose top bit is set.
    printf("  syscall exit  %s(%u) = %" PRId64 "%s\n", name != NULL ? name : "syscall",
           syscall->number, syscall->result, syscall->error ? " (error)" : "");
}

// Appends the function an address falls inside, when there is one. Silence is
// the honest answer for a stripped binary, or for an address in the loader.
static void symbol_print_at(const struct elf *elf, uint64_t load_bias, uint64_t address) {
    if (elf == NULL) return;
    assert(elf->size_bytes > 0);

    uint64_t address_file = 0;
    if (!elf_address_file(elf, load_bias, address, &address_file)) return;

    const Elf64_Sym *const symbol = elf_symbol_containing(elf, address_file);
    if (symbol == NULL) return;
    if (ELF64_ST_TYPE(symbol->st_info) != STT_FUNC) return;

    const char *const name = elf_symbol_name(elf, symbol);
    if (name == NULL) return;

    assert(address_file >= symbol->st_value);
    const uint64_t offset = address_file - symbol->st_value;
    if (offset == 0) {
        printf(" (%s)", name);
    } else {
        printf(" (%s+%" PRIu64 ")", name, offset);
    }
}

// symbol <name>        where a name lives at runtime
// symbol -a <address>  what lives at an address
static void command_symbol(const struct elf *elf, uint64_t load_bias, char *const words[],
                           uint32_t count) {
    assert(elf != NULL);
    assert(words != NULL);
    assert(count >= 1);

    if (count == 3) {
        if (strcmp(words[1], "-a") == 0) {
            uint64_t address = 0;
            if (!value_parse(words[2], &address)) {
                fprintf(stderr, "not an address: %s\n", words[2]);
                return;
            }
            printf("0x%016" PRIx64, address);
            symbol_print_at(elf, load_bias, address);
            printf("\n");
            return;
        }
    }

    if (count == 2) {
        const Elf64_Sym *const symbol = elf_symbol_by_name(elf, words[1]);
        if (symbol == NULL) {
            fprintf(stderr, "no symbol named %s\n", words[1]);
            return;
        }

        // A symbol in no section has no runtime address: an undefined import
        // carries st_value 0, which would otherwise print as the load bias.
        uint64_t address = 0;
        if (!elf_address_virtual(elf, load_bias, symbol->st_value, &address)) {
            fprintf(stderr, "%s has no runtime address\n", words[1]);
            return;
        }
        printf("%-16s 0x%016" PRIx64 "  %" PRIu64 " bytes\n", words[1], address,
               symbol->st_size);
        return;
    }

    help_symbol();
}

static void help_symbol(void) {
    printf("symbol <name>        the runtime address of a name\n");
    printf("symbol -a <address>  the function containing an address\n");
}

static void command_function(const struct elf *elf, struct dwarf *dwarf, uint64_t load_bias,
                             char *const words[], uint32_t count) {
    assert(elf != NULL);
    assert(dwarf != NULL);
    assert(words != NULL);
    assert(count >= 1);

    struct dwarf_function_info info = {0};

    if (count == 3) {
        if (strcmp(words[1], "-a") == 0) {
            uint64_t address_virtual = 0;
            if (!value_parse(words[2], &address_virtual)) {
                fprintf(stderr, "not an address: %s\n", words[2]);
                return;
            }
            // The tracee's addresses and the file's differ by the load bias, and
            // an address in no section of this file belongs to no function of it.
            uint64_t address_file = 0;
            if (!elf_address_file(elf, load_bias, address_virtual, &address_file)) {
                fprintf(stderr, "0x%016" PRIx64 " is not in this file\n", address_virtual);
                return;
            }
            if (!dwarf_function_containing(dwarf, address_file, &info)) {
                fprintf(stderr, "no function at 0x%016" PRIx64 "\n", address_virtual);
                return;
            }
            printf("%s+%" PRIu64 "  [0x%016" PRIx64 ", 0x%016" PRIx64 ")\n",
                   info.name != NULL ? info.name : "(anonymous)",
                   address_file - info.low_pc, info.low_pc + load_bias,
                   info.high_pc + load_bias);
            return;
        }
    }

    if (count == 2) {
        if (!dwarf_function_by_name(dwarf, words[1], &info)) {
            fprintf(stderr, "no function named %s\n", words[1]);
            return;
        }
        printf("%-16s 0x%016" PRIx64 "  %" PRIu64 " bytes\n", words[1],
               info.low_pc + load_bias, info.high_pc - info.low_pc);
        return;
    }

    help_function();
}

static void help_function(void) {
    printf("function <name>        the address of a function, from DWARF\n");
    printf("function -a <address>  the function containing an address, from DWARF\n");
}

static void command_catchpoint(struct control *c, char *const words[], uint32_t count) {
    assert(c != NULL);
    assert(words != NULL);
    assert(count >= 1);

    if (count < 2) {
        help_catchpoint();
        return;
    }

    if (!prefix_match(words[1], "syscall")) {
        help_catchpoint();
        return;
    }

    if(count == 2) {
        if(control_catch_syscalls(c, CONTROL_CATCH_ALL, NULL, 0) == -1) return;
        printf("catching all syscalls\n");
        return;
    }

    if(strcmp(words[2], "none") == 0) {
        if(control_catch_syscalls(c, CONTROL_CATCH_NONE, NULL, 0) == -1) return;
        printf("catching no syscalls\n");
        return;
    }

    uint16_t numbers[control_syscalls_max];
    const uint32_t parsed = syscalls_parse(words[2], numbers, control_syscalls_max);
    if(parsed == 0) {
        fprintf(stderr, "expected syscalls like write, openat or 1,257: %s\n", words[2]);
        return;
    }

        if (control_catch_syscalls(c, CONTROL_CATCH_SOME, numbers, parsed) == -1) return;

    printf("catching");
    for (uint32_t index = 0; index < parsed; index++) {
        const char *const name = syscall_name(numbers[index]);
        printf(" %s(%u)", name != NULL ? name : "unknown", numbers[index]);
    }
    printf("\n");
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
    if (prefix_match(words[1], "catchpoint")) {
        help_catchpoint();
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
    // Same two-character floor as the dispatch, for the same reason: "help s"
    // must not resolve to whichever of step and symbol is tested first.
    if (prefix_match_least(words[1], "symbol", 2)) {
        help_symbol();
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
    printf("symbol       look a name or an address up in the symbol table\n");
    printf("catchpoint   stop on syscalls entering or leaving the kernel\n");
    printf("function <name>        the address of a function, from DWARF\n");
    printf("function -a <address>  the function containing an address, from DWARF\n");
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
static void help_catchpoint(void) {
    printf("catchpoint syscall              every syscall, entry and exit\n");
    printf("catchpoint syscall none         no syscalls (the default)\n");
    printf("catchpoint syscall <list>       by name or number: write,openat or 1,257\n");
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
// Parses "write,openat" or "1,257" into syscall numbers, returning the count.
// Returns 0 for anything malformed, which is a safe failure value because a
// zero-syscall catchpoint is meaningless and so can never be a real answer.
static uint32_t syscalls_parse(const char *text, uint16_t *out, uint32_t count_max) {
    assert(text != NULL);
    assert(out != NULL);
    assert(count_max > 0);

    const char *cursor = text;
    uint32_t count = 0;

    // Bounded (5.6): one syscall per pass, so count_max passes is a ceiling no
    // well-formed input can reach.
    for (uint32_t pass = 0; pass < count_max; pass++) {
        const size_t length = strcspn(cursor, ",");
        if (length == 0) return 0;  // An empty token: "", ",read" or "read,,write".

        uint16_t number = 0;
        if (!syscalls_parse_one(cursor, length, &number)) return 0;

        out[count] = number;
        count++;
        cursor += length;

        if (*cursor == '\0') break;
        assert(*cursor == ',');  // strcspn stopped, so it stopped on a comma.
        cursor++;
    }

    if (*cursor != '\0') return 0;  // More syscalls than count_max.

    assert(count > 0);
    assert(count <= count_max);
    return count;
}

// One token of that list, by name or by number. Named for its caller so the
// call history reads off the page.
static bool syscalls_parse_one(const char *token, size_t length, uint16_t *out) {
    assert(token != NULL);
    assert(length > 0);
    assert(out != NULL);

    // strtoul and syscall_number both want a NUL, and a token is a slice of a
    // longer string, so it is copied before either of them sees it.
    if (length >= main_syscall_name_bytes_max) return false;

    char name[main_syscall_name_bytes_max];
    memcpy(name, token, length);
    name[length] = '\0';

    // A leading digit means a number, anything else means a name. Deciding on
    // the first character, rather than trying strtoul and falling back on
    // failure, keeps the two dialects from overlapping: base 0 would otherwise
    // read a name beginning with a hex digit as a partial number.
    //
    // The cast is not decoration: isdigit is undefined for a negative char, and
    // char is signed on x86-64.
    if (!isdigit((unsigned char)name[0])) {
        return syscall_number(name, out);
    }

    // Base 0, so 1, 0x1 and 01 all work, matching value_parse and bytes_parse
    // rather than inventing a third numeric dialect for the same debugger.
    char *end = NULL;
    errno = 0;
    const unsigned long value = strtoul(name, &end, 0);

    if (errno != 0) return false;     // Out of range for an unsigned long.
    if (end == name) return false;    // No digits at all.
    if (*end != '\0') return false;   // Trailing junk, e.g. "1x".
    if (value > UINT16_MAX) return false;

    *out = (uint16_t)value;
    return true;
}

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
