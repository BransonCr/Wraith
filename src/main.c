//It's at this point I realize that no libraries is painful, but I don't
//want to use everything and take away the entire point of the project, so here lies the only libraries I will use
#include <stdlib.h>     // printf
#include <stdio.h>      // strtol
#include <sys/wait.h>   // waitpid, WIFSTOPPED,
#include <sys/ptrace.h> // ptrace
#include <sys/user.h>   // Struct user_regs_struct
//Basically we just want both paths (launch, attach) to do the exact same thing
//1.)get the tracee into a ptrace-stop
//2.)waitpid until the kernel says it's stopped.
//3.) Ptrace_GETREGS into a user_regs_struct, read regs.rip
//
static int read_and_print_regs(pid_t pid) {
    struct user_regs_struct regs;
    //Using the legacy code with strict struct
    if(ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1){
        perror("PTRACE_GETREGS");
        return -1;
    }
    printf("rip = 0x%llx\n", regs.rip);
    printf("rsp = 0x%llx\n", regs.rsp);
    printf("rbp = 0x%llx\n", regs.rbp);
    printf("rax = 0x%llx\n", regs.rax);
    return 0;
}
int main(int argc, char **argv) {
    if(argc != 2) {
        fprintf(stderr, "usage; %s <pid>\n", argv[0]);
        return  1;
    }
    pid_t pid =  (pid_t) strtol(argv[1], NULL, 10);

    // 1. Grab the process, sens SIGSTOP, return BEFORE it stops
    if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1){
        perror("PTRACE_ATTACH: could not attach");
        return 1;
    }

    // 2. Sync point, block until the tracee has actually frozen
    int status;
    if(waitpid(pid,  &status, 0) == -1 ){
        perror("waitpid");
        return 1;
    }
    if(!WIFSTOPPED(status)){
        fprintf(stderr, "target did not stop when asked (status 0x%x)\n", status);
        return 1;
    }
    // 3. read the registers now that it's stopeed
    read_and_print_regs(pid);

    // 4. let it run BB
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

static int launch(char **argv){
    return 0;
}
static int attach(pid_t pid){
    return 0;
}
