// target.c — one loud syscall, one signal, one obvious hang if the signal is
// swallowed. Built -O0 -no-pie so its addresses survive across runs.
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static volatile sig_atomic_t arrived = 0;

static void handler(int signal_number) {
    (void)signal_number;
    arrived = 1;
}

int main(void) {
    signal(SIGUSR1, handler);

    printf("target %d up\n", getpid());
    fflush(stdout);

    // If the debugger forwards SIGUSR1 this loop ends. If it swallows it, this
    // loop is where the program sits forever, which is the whole point.
    while (arrived == 0) {
        pause();
    }

    write(STDOUT_FILENO, "signal arrived\n", 15);
    return 0;
}
