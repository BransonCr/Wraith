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

// Lifecycle of a traced process. Both launch and attach land in PROC_STOPPED.
enum process_state {
    PROC_STOPPED,
    PROC_RUNNING,
    PROC_EXITED,
    PROC_TERMINATED,
};

// A decoded waitpid status. info is the exit code (PROC_EXITED) or the
// signal number (PROC_STOPPED / PROC_TERMINATED).
struct stop_reason {
    enum process_state reason;
    uint8_t info;
};


struct process {
    struct user_regs_struct registers;
    bool registers_dirty;
    pid_t pid;
    enum process_state state;
    bool registers_valid;
    bool terminate_on_end;
};

int process_launch(const char *path, struct process *out);
int process_attach(pid_t pid, struct process *out);

// Syscall budget: 1 (PTRACE_CONT), or 0 when the tracee is already gone.
// Allocation: none.
int process_resume(struct process *p);

// Blocks until the tracee stops, exits, or dies, and updates p->state.
// Syscall budget: 1 (waitpid), plus 1 per EINTR retry.
// Allocation: none.
struct stop_reason process_wait(struct process *p);

// The register block for the current stop, or NULL on failure.
// Syscall budget: 1 (PTRACE_GETREGSET) on the first call per stop, 0 after.
// Allocation: none. The block lives inside *p.
const struct user_regs_struct *process_registers(struct process *p);

// Syscall budget: up to 6 (SIGSTOP, waitpid, DETACH, SIGCONT, SIGKILL, waitpid).
// Allocation: none.
int process_detach(struct process *p);

// Copies the caller's edited block into the stop cache and marks it dirty
//n your milestone table. notes/index.md maps milestone 1 to book ch. 3+5 and milestone 2 to ch. 7+8 — nothing claims 6. I built what you described (registers wired to the command line), which is the natural close of ch. 5. If ch. 6 is something else in the book, say what and I'll scope it.

// the tracee is not touched here: the flush is one PTRACE_SETREGSET. at the next
// resume, so editing ten registers before continuing costs one syscall, not ten!!!
// the UI layer never holds a mutable pointer into this cache so the cache
// cannot go stale
// no allocations
// syscall budget: 0
int process_registers_set(struct process *p, const struct user_regs_struct *registers);

bool process_gone(const struct process *p);
#endif  // closes the #ifndef at the top of the file
