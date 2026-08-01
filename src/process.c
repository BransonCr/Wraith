// Wraith's ptrace layer. Every syscall that touches the tracee lives here, so
// nothing else in the debugger includes <sys/ptrace.h> and the syscall budget
// of the whole program is auditable in one file (6.1).
//
// _GNU_SOURCE must precede every include. It is what exposes pipe2(2), and we
// want the atomic pipe-with-O_CLOEXEC rather than pipe(2) plus two fcntl calls.
#define _GNU_SOURCE

#include <process.h>

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

int process_step(struct process *p) {
    assert(p != NULL);
    assert(p->pid > 0);

    //Deliverately a near-copy of  process_resume rather tahn a shared helper
    // parameterised by the request.
    //
    if (p->state == PROC_STOPPED) {
        if (process_registers_flush(p) == -1) return -1; //DIRTY
        if (ptrace(PTRACE_SINGLESTEP, p->pid, NULL, NULL) == -1) {
            perror("PTRACE_SINGLESTEP");
            return -1;
        }
        p->registers_valid = false;  // It is executing again; the cache is history.
        p->state = PROC_RUNNING;
        return 0;
    } else {
        fprintf(stderr, "process %d is not stopped, nothing to step\n", p->pid);
        return -1;
    }
}

int process_resume(struct process *p) {
    assert(p != NULL);
    assert(p->pid > 0);

    // A tracee that has exited cannot be continued. Checking state first turns
    // a guaranteed-to-fail syscall into no syscall at all (6.1), and gives the
    // caller a better message than ESRCH.
    if (p->state == PROC_STOPPED) {
        // The edit must reach the tracee before it runs again, or write the user
        if (process_registers_flush(p) == -1) return -1;
        if (ptrace(PTRACE_CONT, p->pid, NULL, NULL) == -1) {
            perror("PTRACE_CONT");
            return -1;
        }
        p->registers_valid = false;  // It is executing again; the cache is history.
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
            if (WIFSTOPPED(status)) {
                reason.reason = PROC_STOPPED;
                reason.info = (uint8_t)WSTOPSIG(status);
            } else {
                assert(false);  // Our reading of the status word is wrong.
            }
        }
    }

    assert(reason.reason != PROC_RUNNING);
    p->state = reason.reason;
    return reason;
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

    // 6.6: options are per-tracee state, set once here and never per stop.
    // EXITKILL only for a process we spawned. Killing one we merely attached
    // to, because our own process ended, is not ours to do.
    if (terminate_on_end) {
        if (ptrace(PTRACE_SETOPTIONS, pid, NULL,
                   (void *)(uintptr_t)PTRACE_O_EXITKILL) == -1) {
            perror("PTRACE_SETOPTIONS");
            return -1;
        }
    }

    assert(out->state == PROC_STOPPED);
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

