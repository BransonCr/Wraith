// Chapter 4 — automated tests for the process module.
// No framework (no-libs rule): plain assert. A failed assert prints
// file:line and aborts; reaching the end means everything passed.
#include <process.h>
#include <assert.h>
#include <signal.h>   // kill
#include <stdio.h>    // snprintf, fopen, fgets
#include <string.h>   // strrchr
#include <sys/wait.h> // waitpid
#include <unistd.h>   // fork, execlp, _exit

// Read the state character from /proc/<pid>/stat.
// Format: "pid (comm) S ..." — comm can contain spaces and ')',
// so find the LAST ')' and take the char two past it.
static char get_process_state(pid_t pid) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        return '\0';
    }
    char buf[256];
    if (!fgets(buf, sizeof buf, f)) {
        fclose(f); return '\0';
    }
    fclose(f);
    char *p = strrchr(buf, ')');
    return (p && p[1]) ? p[2] : '\0';
}

// fork+exec a quiet long-lived target we can attach to (NOT traced by us yet)
static pid_t spawn_target(void) {
    pid_t pid = fork();
    if (pid == 0) {
        freopen("/dev/null", "w", stdout); // yes spams stdout
        execlp("yes", "yes", NULL);
        _exit(127);
    }
    return pid;
}

static void test_launch_success(void) {
    struct process p;
    assert(process_launch("yes", &p) == 0);
    assert(get_process_state(p.pid) == 't'); // t = tracing stop
    process_detach(&p); // terminate_on_end kills it
}

// FAILS until process_launch grows the O_CLOEXEC pipe — the child's
// exec failure is currently invisible to the parent. That's the point:
// this test drives the chapter 4 fix.
static void test_launch_no_such_program(void) {
    struct process p;
    assert(process_launch("you_do_not_have_to_be_good", &p) == -1);
}

static void test_attach_success(void) {
    pid_t target = spawn_target();
    struct process p;
    assert(process_attach(target, &p) == 0);
    assert(get_process_state(target) == 't');
    process_detach(&p); // terminate_on_end is false: target survives
    kill(target, SIGKILL); // so clean it up ourselves
    waitpid(target, NULL, 0);
}

static void test_attach_invalid_pid(void) {
    struct process p;
    assert(process_attach(0, &p) == -1);
}

static void test_resume_success(void) {
    struct process p;
    assert(process_launch("yes", &p) == 0);
    assert(process_resume(&p) == 0);
    char s = get_process_state(p.pid);
    assert(s == 'R' || s == 'S'); // running, or sleeping in a syscall
    process_detach(&p);
}

static void test_resume_already_exited(void) {
    struct process p;
    assert(process_launch("/bin/true", &p) == 0);
    assert(process_resume(&p) == 0);
    struct stop_reason r = process_wait(&p);
    assert(r.reason == PROC_EXITED);
    assert(process_resume(&p) == -1); // no tracee left to continue
}

int main(void) {
    test_launch_success();
    test_launch_no_such_program();
    test_attach_success();
    test_attach_invalid_pid();
    test_resume_success();
    test_resume_already_exited();
    printf("all tests passed\n");
    return 0;
}
