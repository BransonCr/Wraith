// Wraith's ptrace layer. Every syscall that touches the tracee lives here, so
// nothing else in the debugger includes <sys/ptrace.h> and the syscall budget
// of the whole program is auditable in one file (6.1).
//
// _GNU_SOURCE must precede every include. It is what exposes pipe2(2), and we
// want the atomic pipe-with-O_CLOEXEC rather than pipe(2) plus two fcntl calls.
#define _GNU_SOURCE

#include <process/process.h>

#include <string.h>  // Already present, for strerror. memcpy needs it too.
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>     // strerror

#include <elf.h>        // NT_PRSTATUS
#include <fcntl.h>      // O_CLOEXEC
#include <signal.h>     // kill, SIGSTOP, SIGCONT, SIGKILL
#include <sys/ptrace.h> // ptrace
#include <sys/uio.h>    // struct iovec
#include <sys/wait.h>   // waitpid, WIF* macros
#include <unistd.h>     // fork, execlp, pipe2, read, write, close, _exit

// Helpers, declared up front so a reader meets the entry points first.
static void process_stop_classify(pid_t pid, int signal_number, struct stop_reason *reason_out);
static int process_start(struct process *out, pid_t pid, bool terminate_on_end);
static _Noreturn void process_launch_child_fail(int pipe_write, int error_number);
static pid_t process_wait_uninterrupted(pid_t pid, int *status);
static int process_signal(pid_t pid, int signal_number);
static int process_reap(pid_t pid);
static int process_registers_flush(struct process *p);
int process_launch(const char *path, struct process *out) {
    assert(path != NULL);
    assert(out != NULL);

    // The exec-status pipe. O_CLOEXEC is the whole trick: a successful exec
    // closes the write end for me, so the parent's read sees EOF and reads
    // that as "exec worked". A failed exec writes its errno through it first.
    int status_pipe[2] = {-1, -1};
    if (pipe2(status_pipe, O_CLOEXEC) == -1) {
        perror("pipe2");
        return -1;
    }

    const pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        close(status_pipe[0]);
        close(status_pipe[1]);
        return -1;
    }

     if (pid == 0) {
        // --- CHILD ---
        close(status_pipe[0]);

        // Leave wraith's process group before exec, so the terminal's ctrl-C
        // reaches only the debugger. Otherwise the tty delivers SIGINT to the
        // tracee directly and races the SIGSTOP the handler is sending it.
        // The cost is that the tracee is no longer the foreground group, so a
        // debuggee that reads from the terminal now earns SIGTTIN.
        if (setpgid(0, 0) == -1) {
            process_launch_child_fail(status_pipe[1], errno);
        }

        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            process_launch_child_fail(status_pipe[1], errno);
        }
        execlp(path, path, NULL);
        process_launch_child_fail(status_pipe[1], errno);
    }

    // --- PARENT --- we spawned it, so we kill it on the way out.
    close(status_pipe[1]);

    int child_errno = 0;
    const ssize_t bytes_read = read(status_pipe[0], &child_errno, sizeof child_errno);
    close(status_pipe[0]);
    assert(bytes_read <= (ssize_t)sizeof child_errno);

    if (bytes_read == 0) return process_start(out, pid, true);

    // Anything but EOF means the child never reached main. Say why, and reap
    // it so we do not leave a zombie behind.
    if (bytes_read == (ssize_t)sizeof child_errno) {
        fprintf(stderr, "launch %s: %s\n", path, strerror(child_errno));
    } else {
        perror("read");
    }
    process_reap(pid);  // Best effort; the launch has already failed.
    return -1;
}

int process_attach(pid_t pid, struct process *out) {
    assert(out != NULL);

    // A bad pid is an operating error, not a programmer error: it comes from
    // the user, so it is validated and reported, never asserted.
    if (pid <= 0) {
        fprintf(stderr, "invalid pid: %d\n", pid);
        return -1;
    }

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("PTRACE_ATTACH");
        return -1;
    }
    return process_start(out, pid, false);
}

int process_step(struct process *p, int signal_number) {
    assert(p != NULL);
    assert(p->pid > 0);
    assert(signal_number >= 0);

    if (p->state == PROC_STOPPED) {
        if (process_registers_flush(p) == -1) return -1;
        if (ptrace(PTRACE_SINGLESTEP, p->pid, NULL,
                   (void *)(uintptr_t)signal_number) == -1) {
            perror("PTRACE_SINGLESTEP");
            return -1;
        }
        p->registers_valid = false;  // It is executing again; the cache is history.
        p->syscall_valid = false;
        p->state = PROC_RUNNING;
        return 0;
    } else {
        fprintf(stderr, "process %d is not stopped, nothing to step\n", p->pid);
        return -1;
    }
}

int process_resume(struct process *p, int signal_number) {
    assert(p != NULL);
    assert(p->pid > 0);
    assert(signal_number >= 0);

    // A tracee that has exited cannot be continued. Checking state first turns
    // a guaranteed-to-fail syscall into no syscall at all (6.1), and gives the
    // caller a better message than ESRCH.
    if (p->state == PROC_STOPPED) {
        // The edit must reach the tracee before it runs again.
        if (process_registers_flush(p) == -1) return -1;
        if (ptrace(PTRACE_CONT, p->pid, NULL,
                   (void *)(uintptr_t)signal_number) == -1) {
            perror("PTRACE_CONT");
            return -1;
        }
        p->registers_valid = false;
        p->syscall_valid = false;
        p->state = PROC_RUNNING;
        return 0;
    } else {
        fprintf(stderr, "process %d is not stopped, nothing to continue\n", p->pid);
        return -1;
    }
}

// A third near-copy rather than a request parameter, for the same reason
// process_step is one: the ptrace request stays readable at the call site, and
// the caller's choice between cheap and expensive resume is a branch the caller
// writes rather than a flag it fills in.
int process_resume_syscall(struct process *p, int signal_number) {
    assert(p != NULL);
    assert(p->pid > 0);
    assert(signal_number >= 0);

    if (p->state == PROC_STOPPED) {
        if (process_registers_flush(p) == -1) return -1;
        if (ptrace(PTRACE_SYSCALL, p->pid, NULL,
                   (void *)(uintptr_t)signal_number) == -1) {
            perror("PTRACE_SYSCALL");
            return -1;
        }
        p->registers_valid = false;
        p->syscall_valid = false;
        p->state = PROC_RUNNING;
        return 0;
    } else {
        fprintf(stderr, "process %d is not stopped, nothing to continue\n", p->pid);
        return -1;
    }
}
struct stop_reason process_wait(struct process *p) {
    assert(p != NULL);
    assert(p->pid > 0);

    // Invalidate before the wait, not after: no path may read a register block
    // that describes a moment already gone (place-of-check to place-of-use).
    p->registers_dirty = false;
    p->registers_valid = false;

    // If waitpid itself fails we do not know what the tracee is doing, so the
    // default says "not stopped" and every caller treats it as failure.
    struct stop_reason reason = {.reason = PROC_TERMINATED, .info = 0};

    int status = 0;
    if (process_wait_uninterrupted(p->pid, &status) == -1) {
        perror("waitpid");
        p->state = reason.reason;
        return reason;
    }

    if (WIFEXITED(status)) {
        reason.reason = PROC_EXITED;
        reason.info = (uint8_t)WEXITSTATUS(status);
    } else {
        if (WIFSIGNALED(status)) {
            reason.reason = PROC_TERMINATED;
            reason.info = (uint8_t)WTERMSIG(status);
        } else {
            if(WIFSTOPPED(status)) {
                reason.reason = PROC_STOPPED;
                process_stop_classify(p->pid, WSTOPSIG(status), &reason);
            } else {
                assert(false);  // Our reading of the status word is wrong.
            }
        }
    }

    assert(reason.reason != PROC_RUNNING);
    p-> syscall_valid = false;
    p->state = reason.reason;
    return reason;
}

static void process_stop_classify(pid_t pid, int signal_number,
                                  struct stop_reason *reason_out) {
    assert(pid > 0);
    assert(signal_number > 0);
    assert(reason_out != NULL);

    reason_out->trap = PROC_TRAP_NONE;

    if (signal_number == (SIGTRAP | 0x80)) {
        reason_out->trap = PROC_TRAP_SYSCALL;
        reason_out->info = SIGTRAP;
        return;
    }

    reason_out->info = (uint8_t)signal_number;
    if (signal_number != SIGTRAP) return;  // Not a trap, so nothing to classify.

    siginfo_t information = {0};
    if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &information) == -1) {
        perror("PTRACE_GETSIGINFO");
        reason_out->trap = PROC_TRAP_UNKNOWN;
        return;
    }
    assert(information.si_signo == SIGTRAP);

    if (information.si_code == SI_KERNEL) {
        reason_out->trap = PROC_TRAP_BREAKPOINT;
        return;
    }
    if (information.si_code == TRAP_TRACE) {
        reason_out->trap = PROC_TRAP_STEP;
        return;
    }

    reason_out->trap = PROC_TRAP_UNKNOWN;
}

const struct user_regs_struct *process_registers(struct process *p) {
    assert(p != NULL);
    assert(p->pid > 0);

    // The point of 6.5: every read after the first in a stop is free.
    if (p->registers_valid) return &p->registers;

    if (p->state == PROC_STOPPED) {
        // GETREGSET over GETREGS: it carries an explicit size, so the kernel
        // tells us how much it wrote instead of us trusting a fixed layout.
        struct iovec block = {
            .iov_base = &p->registers,
            .iov_len = sizeof p->registers,
        };
        if (ptrace(PTRACE_GETREGSET, p->pid, (void *)(uintptr_t)NT_PRSTATUS,
                   &block) == -1) {
            perror("PTRACE_GETREGSET");
            return NULL;
        }
        assert(block.iov_len == sizeof p->registers);
        p->registers_valid = true;
        return &p->registers;
    } else {
        fprintf(stderr, "process %d is running, its registers are in flight\n", p->pid);
        return NULL;
    }
}
bool process_executable_path(const struct process *p, char *out, uint32_t size_bytes) {
    assert(p != NULL);
    assert(p->pid > 0);
    assert(out != NULL);
    assert(size_bytes > 0);

    const int written = snprintf(out, size_bytes, "/proc/%d/exe", p->pid);
    if (written < 0) return false;
    if ((uint32_t)written >= size_bytes) return false;
    return true;
}

bool process_auxv(const struct process *p, uint64_t type, uint64_t *out) {
    assert(p != NULL);
    assert(p->pid > 0);
    assert(out != NULL);

    char path[64];
    const int written = snprintf(path, sizeof path, "/proc/%d/auxv", p->pid);
    assert(written > 0);
    assert((size_t)written < sizeof path);

    const int descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (descriptor == -1) {
        perror(path);
        return false;
    }

    // The vector is 368 bytes on this kernel, so 64 pairs is a ceiling with
    // room to spare, and reading it whole keeps the scan to one pass.
    enum { auxv_pairs_max = 64 };
    uint64_t pairs[auxv_pairs_max * 2] = {0};
    size_t filled = 0;

    for (uint32_t pass = 0; pass < auxv_pairs_max; pass++) {
        if (filled == sizeof pairs) break;
        const ssize_t moved = read(descriptor, (uint8_t *)pairs + filled,
                                   sizeof pairs - filled);
        if (moved == 0) break;  // A short read is the normal end of a proc file.
        if (moved == -1) {
            if (errno == EINTR) continue;
            perror("read");
            break;
        }
        filled += (size_t)moved;
    }
    if (close(descriptor) == -1) perror("close");

    const uint32_t count = (uint32_t)(filled / (sizeof(uint64_t) * 2));
    for (uint32_t index = 0; index < count; index++) {
        assert(index < auxv_pairs_max);
        if (pairs[index * 2] == AT_NULL) break;
        if (pairs[index * 2] != type) continue;
        *out = pairs[index * 2 + 1];
        return true;
    }
    return false;
}
//syscall result grabber, system call exit recorder.
//
const struct process_syscall *process_syscall(struct process *p) {

    //example usage,
    //write(fd, "hello", 5);
    //p->syscall = (struct process_syscall){
    //     .result = 5,                 // information.exit.rval (5 bytes successfully written)
    //     .number = 1,                 // registers->orig_rax (Syscall #1 is 'write')
    //     .entry = false,              // Mark as an exit event
    //     .error = false,              // information.exit.is_error (no error occurred)
    // };
    assert(p != NULL);
    assert(p->pid > 0);

    if (p->syscall_valid) return &p->syscall;
    if(p->state != PROC_STOPPED) return NULL;

    //Kernel reports entry against exit itself, in this one field.
    struct __ptrace_syscall_info information = {0};
    if(ptrace(PTRACE_GET_SYSCALL_INFO, p->pid, (void *)(uintptr_t) sizeof information, &information) == -1) {
        perror("PTRACE_GET_SYSCALL_INFO");
        return NULL;
    }

       if (information.op == PTRACE_SYSCALL_INFO_ENTRY) {
        p->syscall = (struct process_syscall){
            .number = (uint16_t)information.entry.nr,
            .entry = true,
        };
        static_assert(sizeof p->syscall.arguments == sizeof information.entry.args,
                      "six 64-bit arguments, both sides");
        memcpy(p->syscall.arguments, information.entry.args,
               sizeof p->syscall.arguments);
    } else {
        // op is NONE at every stop that is not a syscall stop, which is also
        // what it reports if TRACESYSGOOD was never set: the kernel derives
        // entry-against-exit from the same bit the option controls.
        if (information.op != PTRACE_SYSCALL_INFO_EXIT) return NULL;

        // The exit record carries the return value but not the number. That
        // still lives in orig_rax, which the kernel preserves across the call
        // precisely so a tracer can ask what the syscall was on the way out.
        const struct user_regs_struct *const registers = process_registers(p);
        if (registers == NULL) return NULL;

        p->syscall = (struct process_syscall){
            .result = information.exit.rval,
            .number = (uint16_t)registers->orig_rax,
            .entry = false,
            .error = information.exit.is_error != 0,
        };
    }

    // One success tail for both branches. Putting it inside the else is how the
    // entry path came to fill the cache and then report nothing was there.
    p->syscall_valid = true;
    return &p->syscall;
}

bool process_gone(const struct process *p) {
    assert(p != NULL);

    if (p->pid == 0) return true;
    if (p->state == PROC_EXITED) return true;
    if (p->state == PROC_TERMINATED) return true;

    assert(p->pid > 0);
    return false;
}

int process_detach(struct process *p) {
    assert(p != NULL);

    // Detaching twice is not an error; the second call has nothing to do.
    if (process_gone(p)) {
        p->pid = 0;
        p->registers_valid = false;
        return 0;
    }
    assert(p->pid > 0);

    int result = 0;

    // PTRACE_DETACH needs a stopped tracee, so stop it if it is running.
    if (p->state == PROC_RUNNING) {
        if (process_signal(p->pid, SIGSTOP) == -1) result = -1;
        if (process_reap(p->pid) == -1) result = -1;
    }
    // An edit is the users to keep even if tha last thing they did was detach
    if(process_registers_flush(p) == -1) result = -1;
    if (ptrace(PTRACE_DETACH, p->pid, NULL, NULL) == -1) {
        perror("PTRACE_DETACH");
        result = -1;
    }
    // We stopped it above, so hand it back running the way we found it.
    if (process_signal(p->pid, SIGCONT) == -1) result = -1;

    if (p->terminate_on_end) {
        if (process_signal(p->pid, SIGKILL) == -1) result = -1;
        if (process_reap(p->pid) == -1) result = -1;
    }

    // pid == 0 is the flag the other calls read, so clear it unconditionally:
    // a failed detach still means we are no longer this process's tracer.
    p->pid = 0;
    p->registers_valid = false;
    return result;
}

// The shared tail of both entry paths. Records the tracee, waits for the stop
// the kernel owes us, and sets the options that last for the whole attachment.
// Both paths end here so that "attached" means exactly one thing.
static int process_start(struct process *out, pid_t pid, bool terminate_on_end) {
    assert(out != NULL);
    assert(pid > 0);

    // One initializer, so every field is written exactly once and nothing
    // survives from whatever the caller's stack held before.
    *out = (struct process){
        .pid = pid,
        .state = PROC_RUNNING,
        .terminate_on_end = terminate_on_end,
        .registers_valid = false,
    };

    const struct stop_reason reason = process_wait(out);
    if (reason.reason != PROC_STOPPED) {
        // It died before we ever saw it stop, so there is nothing to debug.
        fprintf(stderr, "process %d never reached a stop\n", pid);
        out->pid = 0;
        return -1;
    }


    const int options = terminate_on_end
        ? (PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL)
        : PTRACE_O_TRACESYSGOOD;
    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, (void *)(uintptr_t)options) == -1) {
        perror("PTRACE_SETOPTIONS");
        return -1;
    }

    return 0;
}

// Runs only in the child, and only once the launch has already failed: hand
// the parent our errno, then leave. After a successful exec there is no shared
// memory and no return value, so this pipe is the parent's only way to hear.
static _Noreturn void process_launch_child_fail(int pipe_write, int error_number) {
    assert(pipe_write >= 0);

    // A short or interrupted write would cost the parent its diagnosis, so
    // loop; bounded, because an unbounded loop is a hang waiting to happen.
    enum { attempts_max = 8 };
    const uint8_t *const bytes = (const uint8_t *)&error_number;
    size_t written_total = 0;

    for (uint32_t attempt = 0; attempt < attempts_max; attempt++) {
        if (written_total == sizeof error_number) break;
        const ssize_t written = write(pipe_write, bytes + written_total,
                                      sizeof error_number - written_total);
        if (written > 0) {
            written_total += (size_t)written;
        } else {
            if (errno != EINTR) break;
        }
    }
    _exit(127);
}

// waitpid, retrying the interruption every interruptible syscall owes us.
// Bounded (5.6): 64 signals in a row is a broken world, not a slow one.
static pid_t process_wait_uninterrupted(pid_t pid, int *status) {
    assert(pid > 0);
    assert(status != NULL);

    enum { retries_max = 64 };
    for (uint32_t retry = 0; retry < retries_max; retry++) {
        const pid_t waited = waitpid(pid, status, 0);
        if (waited != -1) return waited;
        if (errno != EINTR) return -1;
    }
    errno = EINTR;
    return -1;
}

// kill(2) with the reporting every call site needs, so callers stay one line.
static int process_signal(pid_t pid, int signal_number) {
    assert(pid > 0);
    assert(signal_number > 0);

    if (kill(pid, signal_number) == -1) {
        perror("kill");
        return -1;
    }
    return 0;
}

// Collect a status we are about to throw away, so the tracee does not linger
// as a zombie. Named for what it is for, not for the syscall it makes.
static int process_reap(pid_t pid) {
    assert(pid > 0);

    int status = 0;
    if (process_wait_uninterrupted(pid, &status) == -1) {
        perror("waitpid");
        return -1;
    }
    return 0;
}

int process_registers_set(struct process *p, const struct user_regs_struct *registers) {
    assert(p != NULL);
    assert(registers != NULL);
    assert(p->pid > 0);

    if (p->state == PROC_STOPPED) {
        p->registers = *registers;
        p->registers_dirty = true;
        p->registers_valid = true;
        return 0;
    } else {
        fprintf(stderr, "process %d is still running, its registers are in flight\n", p->pid);
        return -1;
    }
}
static int process_registers_flush(struct process *p) {
    assert(p != NULL);
    assert(p->pid > 0);

    if(p->registers_dirty) {
        assert(p->registers_valid);

        //Mirror GETREGSET above, same not type, same explicit length so the kernel
        //validate the size rather tahn trusting out layout
        struct iovec block = {
            .iov_base = &p->registers,
            .iov_len = sizeof p->registers,
        };
        if (ptrace(PTRACE_SETREGSET, p->pid, (void *)(uintptr_t)NT_PRSTATUS, &block) == -1) {
            perror("PTRACE_SETREGSET");
            return -1;
        }
        assert(block.iov_len == sizeof p->registers);
        p->registers_dirty = false;

    }
    return 0;
}



int64_t process_memory_read(struct process *p, uint64_t address, uint8_t *out, uint32_t size_bytes) {
    assert(p != NULL);
    assert(p->pid > 0);
    assert(out != NULL);
    assert(size_bytes > 0);

    //one crossing for whole range, however long, PTRACE_PEEKDATA
    // would cost a syscall per 8 bytes: 128 for KB, against one here.
    uint32_t moved_total = 0;
    for (uint32_t pass = 0; pass < size_bytes; pass++ ){
        if(moved_total == size_bytes) break;

        struct iovec local = {
            .iov_base = out + moved_total,
            .iov_len = size_bytes - moved_total,
        };
        struct iovec remote = {
            .iov_base = (void *)(uintptr_t)(address+ moved_total),
            .iov_len = size_bytes - moved_total,
        };

        const ssize_t moved = process_vm_readv(p->pid, &local, 1, &remote, 1, 0);
        if (moved == -1) {
            // A hole in the address space ends the read rather than failing.
            if (moved_total == 0) {
                perror("process_vm_readv");   // typo'd "readv" as "ready"
                return -1;
            }
            break;
        }
        if (moved == 0) break;
        moved_total += (uint32_t)moved;
    }

    if (moved_total == 0) return -1;
    assert(moved_total <= size_bytes);
    return (int64_t)moved_total;
}


int process_memory_write(struct process *p, uint64_t address,
                         const uint8_t *source, uint32_t size_bytes) {
    assert(p != NULL);
    assert(p->pid > 0);
    assert(source != NULL);
    assert(size_bytes > 0);

    const uint32_t word_size = (uint32_t)sizeof(long);
    uint32_t written_total = 0;

    // Bounded (5.6): every pass writes at least one byte, so size_bytes passes
    // is a ceiling no correct run can reach.
    for (uint32_t pass = 0; pass < size_bytes; pass++) {
        if (written_total == size_bytes) break;

        const uint64_t word_address = address + written_total;
        const uint32_t remaining = size_bytes - written_total;
        const uint32_t chunk = remaining < word_size ? remaining : word_size;

        // POKEDATA moves a whole word and has no narrower setting. A full word
        // of ours is overwritten completely, so reading it first would be a
        // wasted syscall. A partial tail is not: without the read, the bytes
        // past our data go back as zeroes and we erase what we never looked at.
        long word = 0;
        if (chunk < word_size) {
            errno = 0;  // PEEK returns the word itself, so -1 alone is ambiguous.
            //peeking at registers
            word = ptrace(PTRACE_PEEKDATA, p->pid,
                          (void *)(uintptr_t)word_address, NULL);
            if (word == -1 && errno != 0) {
                perror("PTRACE_PEEKDATA");
                return -1;
            }
        }

        // Little-endian: byte 0 of the word is the byte at word_address, so the
        // low end of `word` is the end that lands first in memory.
        memcpy(&word, source + written_total, chunk);
        if (ptrace(PTRACE_POKEDATA, p->pid, (void *)(uintptr_t)word_address,
                   (void *)(uintptr_t)word) == -1) {
            perror("PTRACE_POKEDATA");
            return -1;
        }
        written_total += chunk;
    }

    assert(written_total == size_bytes);
    return 0;
}

