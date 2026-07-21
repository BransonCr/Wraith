// Include guard. #include is literal text pasting, so a header pulled in twice
// would redefine these structs, which is a compile error. The guard prevents it:
//   #ifndef  - "if this macro is NOT defined, compile everything down to #endif"
//   #define  - define it immediately, so a second #include finds it already set
//              and skips the whole body.
// The name is arbitrary but must be unique across every header in the build,
// hence the WRAITH_ prefix. (#pragma once does the same in one line, but is not
// standard C, just universally supported.)
#ifndef WRAITH_PROCESS_H
#define WRAITH_PROCESS_H

#include <stdbool.h>
#include <sys/types.h>  // pid_t

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
    unsigned char info;
};

struct process {
    pid_t pid;
    enum process_state state;
    bool terminate_on_end;  // true if we spawned it, so we kill it on the way out
};

// Both return 0 on success, -1 on failure (message already printed via perror).
// On success *out is filled in and the tracee is stopped.
int process_launch(const char *path, struct process *out);
int process_attach(pid_t pid, struct process *out);

int process_resume(struct process *p);
struct stop_reason process_wait(struct process *p);
void process_detach(struct process *p);

#endif  // closes the #ifndef at the top of the file
