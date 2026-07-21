#include <process.h>

#include <stdio.h>      // perror
#include <signal.h>     // kill, SIGSTOP, SIGCONT, SIGKILL
#include <unistd.h>     // fork, execlp, _exit
#include <sys/wait.h>   // waitpid, WIF* macros
#include <sys/ptrace.h> // ptrace

int process_launch(const char *path, struct process *out) {
    (void)path; (void)out;
    return -1;
}

int process_attach(pid_t pid, struct process *out) {
    (void)pid; (void)out;
    return -1;
}

int process_resume(struct process *p) {
    (void)p;
    return -1;
}

struct stop_reason process_wait(struct process *p) {
    (void)p;
    struct stop_reason r = { PROC_STOPPED, 0 };
    return r;
}

void process_detach(struct process *p) {
    (void)p;
}
