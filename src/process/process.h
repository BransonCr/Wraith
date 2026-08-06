// Include guard. #include is literal text pasting, so a header pulled in twice
// would redefine these structs, which is a compile error. The guard prevents it:
//   #ifndef  - "if this macro is NOT defined, compile everything down to #endif"
//   #define  - define it immediately, so a second #include finds it already set
//              and skips the whole body.
// The name is arbitrary but must be unique across every header in the build,
// hence the WRAITH_ prefix. (#pragma once does the same in one line, but is not
// standard C, just universally supported.)
#ifndef WRAITH_PROCESS_H_
#define WRAITH_PROCESS_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>  // pid_t
#include <sys/user.h>

enum process_trap {
    PROC_TRAP_NONE,
    PROC_TRAP_BREAKPOINT,
    PROC_TRAP_STEP,
    PROC_TRAP_SYSCALL,
    PROC_TRAP_UNKNOWN,
};

// Lifecycle of a traced process. Both launch and attach land in PROC_STOPPED.
enum process_state {
    PROC_STOPPED,
    PROC_RUNNING,
    PROC_EXITED,
    PROC_TERMINATED,
};

struct stop_reason {
    enum process_state reason;
    enum process_trap trap;
    uint8_t info;
};

enum { process_syscall_max_arguments = 6 };  // x86-64: rd9 rsi rdx r10 r8 r9
struct process_syscall {
    uint64_t arguments[process_syscall_max_arguments];
    uint64_t result;
    uint16_t number;
    bool error;
    bool entry;
    bool exit;
};

// static_assert(sizeof (struct process_syscall) == 64, "one cache line per stop");

struct process {
    struct user_regs_struct registers;
    struct process_syscall syscall;
    bool registers_dirty;
    pid_t pid;
    enum process_state state;
    bool registers_valid;
    bool syscall_valid;
    bool terminate_on_end;
};

int process_launch(const char *path, struct process *out);
int process_attach(pid_t pid, struct process *out);

int process_resume(struct process *p, int signal_number);
int process_resume_syscall(struct process *p, int signal_number);

struct stop_reason process_wait(struct process *p);

const struct user_regs_struct *process_registers(struct process *p);

// Syscall budget: up to 6 (SIGSTOP, waitpid, DETACH, SIGCONT, SIGKILL, waitpid).
// Allocation: none.
int process_detach(struct process *p);



int process_registers_set(struct process *p, const struct user_regs_struct *registers);

bool process_gone(const struct process *p);


int process_step(struct process *p, int signal_number);

int64_t process_memory_read(struct process *p, uint64_t address, uint8_t *out, uint32_t size_bytes);
int process_memory_write(struct process *p, uint64_t adress, const uint8_t *source, uint32_t size_bytes);
const struct process_syscall *process_syscall(struct process *p);


bool process_auxv(const struct process *p, uint64_t type, uint64_t *out);

bool process_executable_path(const struct process *p, char *out, uint32_t size_bytes);
#endif  // closes the #ifndef at the top of the file
