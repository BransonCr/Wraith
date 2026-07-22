#include <process.h>

#include <stdio.h>      // perror
#include <signal.h>     // kill, SIGSTOP, SIGCONT, SIGKILL
#include <unistd.h>     // fork, execlp, _exit
#include <sys/wait.h>   // waitpid, WIF* macros
#include <sys/ptrace.h> // ptrace
static int finish_attach(struct process *out, pid_t pid, bool terminate_on_end){
    out->pid = pid;
    out->state = PROC_RUNNING;
    out->terminate_on_end = terminate_on_end;
    process_wait(out);
    return 0;
}


int process_launch(const char *path, struct process *out) {
    pid_t pid = fork();
    if(pid == -1){
        perror("fork");
        return -1;
    }
    if(pid == 0){
        // --- CHILD ---0
        if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1){
            perror("PTRACE_TRACEME");
            _exit(127);
            //CH4 fixes it with 0_CLOEXEC pipe. FINE UNTIL THEN
        }
        execlp(path, path, NULL);
        perror("execlp");
        _exit(127);

    }
    // --- PARENT --- we spawned so kill
    return finish_attach(out,pid, true);
}

int process_attach(pid_t pid, struct process *out) {
    if (pid <= 0){
        fprintf(stderr, "Invalid pid: %d\n", pid);
        return -1;
    }

    if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1){
        perror("PTRACE_ATTACH");
        return -1;
    }
    return finish_attach(out, pid, false);
}

int process_resume(struct process *p) {
    if (ptrace(PTRACE_CONT, p->pid, NULL, NULL) == -1){
        perror("PTRACE_CONT");
        return -1;
    }
    p->state = PROC_RUNNING;
    return 0;
}

struct stop_reason process_wait(struct process *p) {
    int status;
    struct stop_reason r = {PROC_STOPPED, 0};

    if(waitpid(p->pid, &status, 0) == -1){
        perror("waitpid");
        return r;
    }

    if (WIFEXITED(status)) {
        r.reason = PROC_EXITED;
        r.info = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        r.reason = PROC_TERMINATED;
        r.info = WTERMSIG(status);
    } else if (WIFSTOPPED(status)) {
        r.reason = PROC_STOPPED;
        r.info = WSTOPSIG(status);
    }

    p->state = r.reason;
    return r;
}

void process_detach(struct process *p) {
    if (p->pid == 0) return ;

    //PTRACE_DETACH needs a stopped tracee; stop if it is running
    if(p->state == PROC_RUNNING){
        kill(p->pid, SIGSTOP);
        int status;
        waitpid(p->pid, &status, 0);
    }

    ptrace(PTRACE_DETACH, p->pid, NULL, NULL);
    kill(p->pid, SIGCONT);

    if (p->terminate_on_end) {
        kill(p->pid, SIGKILL);
        int status;
        waitpid(p->pid, &status, 0);
    }
    p->pid = 0;
}
