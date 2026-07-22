//It's at this point I realize that no libraries is painful, but I don't
//want to use everything and take away the entire point of the project, so here lies the only libraries I will use
#include <process.h>    // attach|launch
#include <stdlib.h>     // printf
#include <stdio.h>      // strtol
#include <sys/types.h>
#include <sys/wait.h>   // waitpid, WIFSTOPPED,
#include <sys/ptrace.h> // ptrace
#include <sys/user.h>   // Struct user_regs_struct
#include <string.h>     // strcmp
//Basically we just want both paths (launch, attach) to do the exact same thing
//1.)get the tracee into a ptrace-stop
//2.)waitpid until the kernel says it's stopped.
//3.) Ptrace_GETREGS into a user_regs_struct, read regs.rip
static int read_and_print_regs(pid_t pid) {
    struct user_regs_struct regs;
    //Using the legacy code with strict struct
    if(ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1){
        perror("PTRACE_GETREGS");
        return -1;
    }
    // rip: instruction pointer, address of the next instruction to execute.
    //      This is "where the process is" the moment we froze it.
    printf("rip = 0x%llx\n", regs.rip);
    // rsp: stack pointer, top of the stack (stack grows downward on x86-64).
    printf("rsp = 0x%llx\n", regs.rsp);
    // rbp: base/frame pointer, bottom of the current call frame. rsp..rbp is
    //      the current function's frame, so rbp is what a backtrace walks.
    //      May be garbage if compiled with -fomit-frame-pointer.
    printf("rbp = 0x%llx\n", regs.rbp);
    // rax: general purpose, by convention holds the return value / syscall number.
    printf("rax = 0x%llx\n", regs.rax);
    return 0;
}


int main(int argc, char **argv){
    struct process proc;

    if (argc == 3 && strcmp(argv[1], "-p") == 0) {
    // wraith -p <pid>  → attach to an existing process
        pid_t pid = (pid_t) strtol(argv[2], NULL, 10);
    if (process_attach(pid, &proc) == -1) return 1;
    } else if (argc == 2) {
        // wraith <program> → launch and trace it
        if (process_launch(argv[1], &proc) == -1) return 1;
    } else {
        fprintf(stderr, "usage: %s <program> | -p <pid>\n", argv[0]);
        return 1;
    }

    read_and_print_regs(proc.pid);

    process_detach(&proc);
    return 0;
}

