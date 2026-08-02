// Wraith's run-control layer. It owns the one trick that makes a debugger a
// debugger: swap the first byte of an instruction for 0xCC, let the CPU fault
// into the kernel, and catch the SIGTRAP the kernel sends the tracer.
//
// This layer knows what a breakpoint is. The layer below it knows only bytes
// and addresses, and this file is the only place that turns one into the other.
#include <control.h>

#include <assert.h>
#include <inttypes.h>  // PRIx64
#include <signal.h>    // SIGTRAP
#include <stdio.h>     // fprintf

static struct control_breakpoint *control_find_by_id(struct control *c, uint32_t id);
static struct control_breakpoint *control_find_by_address(struct control *c, uint64_t address);
static int control_arm(struct control_breakpoint *breakpoint, struct process *p);
static int control_disarm(struct control_breakpoint *breakpoint, struct process *p);
static int control_step_over(struct control_breakpoint *breakpoint, struct process *p,
                             struct stop_reason *reason_out);
static void control_rewind(struct control *c, struct process *p);

void control_init(struct control *c) {
    assert(c != NULL);

    *c = (struct control){
        .count = 0,
        .id_next = 1,
    };

    assert(c->count == 0);
    assert(c->id_next == 1);
}

int control_breakpoint_set(struct control *c, struct process *p, uint64_t address,
                           uint32_t *id_out) {
    assert(c != NULL);
    assert(p != NULL);
    assert(id_out != NULL);
    assert(c->count <= control_breakpoints_max);

    if (c->count == control_breakpoints_max) {
        fprintf(stderr, "breakpoint table is full (%d max)\n", control_breakpoints_max);
        return -1;
    }
    if (control_find_by_address(c, address) != NULL) {
        fprintf(stderr, "breakpoint already set at 0x%016" PRIx64 "\n", address);
        return -1;
    }

    struct control_breakpoint *breakpoint = &c->breakpoints[c->count];
    *breakpoint = (struct control_breakpoint){
        .address = address,
        .id = c->id_next,
        .original_byte = 0,
        .enabled = false,
    };

    if (control_arm(breakpoint, p) == -1) return -1;
    assert(breakpoint->enabled);

    *id_out = breakpoint->id;
    c->count++;
    c->id_next++;
    return 0;
}

int control_breakpoint_enable(struct control *c, struct process *p, uint32_t id) {
    assert(c != NULL);
    assert(p != NULL);

    struct control_breakpoint *breakpoint = control_find_by_id(c, id);
    if (breakpoint == NULL) {
        fprintf(stderr, "no breakpoint with id %u\n", id);
        return -1;
    }

    if (breakpoint->enabled) return 0;  // Already armed, nothing to do.
    return control_arm(breakpoint, p);
}

int control_breakpoint_disable(struct control *c, struct process *p, uint32_t id) {
    assert(c != NULL);
    assert(p != NULL);

    struct control_breakpoint *breakpoint = control_find_by_id(c, id);
    if (breakpoint == NULL) {
        fprintf(stderr, "no breakpoint with id %u\n", id);
        return -1;
    }

    // The row survives a disable, so the address and id stay stable and the
    // user can re-enable without retyping either.
    if (!breakpoint->enabled) return 0;  // Already disarmed, nothing to do.
    return control_disarm(breakpoint, p);
}

int control_breakpoint_delete(struct control *c, struct process *p, uint32_t id) {
    assert(c != NULL);
    assert(p != NULL);
    assert(c->count <= control_breakpoints_max);

    struct control_breakpoint *breakpoint = control_find_by_id(c, id);
    if (breakpoint == NULL) {
        fprintf(stderr, "no breakpoint with id %u\n", id);
        return -1;
    }

    if (breakpoint->enabled) {
        if (control_disarm(breakpoint, p) == -1) return -1;
    }

    // Shift the tail down rather than swapping the last row in, so 'list' keeps
    // its id order and a user reading it twice sees the same thing twice.
    const uint32_t position = (uint32_t)(breakpoint - c->breakpoints);
    assert(position < c->count);
    for (uint32_t i = position; i + 1 < c->count; i++) {
        c->breakpoints[i] = c->breakpoints[i + 1];
    }
    c->count--;
    return 0;
}

uint32_t control_breakpoints_count(const struct control *c) {
    assert(c != NULL);
    assert(c->count <= control_breakpoints_max);

    return c->count;
}

const struct control_breakpoint *control_breakpoint_at(const struct control *c, uint32_t index) {
    assert(c != NULL);
    assert(index < c->count);

    return &c->breakpoints[index];
}

// Syscall budget: 2 (SINGLESTEP, waitpid), or 7 when rip sits on a breakpoint.
// Allocation: none.
int control_step(struct control *c, struct process *p, struct stop_reason *reason_out) {
    assert(c != NULL);
    assert(p != NULL);
    assert(reason_out != NULL);

    const struct user_regs_struct *const registers = process_registers(p);
    if (registers == NULL) return -1;

    struct control_breakpoint *const here = control_find_by_address(c, registers->rip);
    if (here != NULL) {
        if (here->enabled) {
            // control_step_over is exactly this operation, so hand the whole
            // step to it rather than duplicating the disarm/step/re-arm dance.
            return control_step_over(here, p, reason_out);
        }
    }

    if (process_step(p) == -1) return -1;
    *reason_out = process_wait(p);

    // No rewind here. The CPU stops before executing a 0xCC it merely landed
    // on, so rip is already the address the user wants to see.
    return 0;
}

int control_continue(struct control *c, struct process *p, struct stop_reason *reason_out) {
    assert(c != NULL);
    assert(p != NULL);
    assert(reason_out != NULL);

    const struct user_regs_struct *const registers = process_registers(p);
    if (registers == NULL) return -1;

    // rip is the address of the next instruction. If our trap is sitting there,
    struct control_breakpoint *const here = control_find_by_address(c, registers->rip);
    if (here != NULL) {
        if (here->enabled) {
            if (control_step_over(here, p, reason_out) == -1) return -1;

            // Only a dead tracee ends the call here. A live one still needs the
            // resume this function promised its caller.
            if (process_gone(p)) return 0;
        }
    }

    if (process_resume(p) == -1) return -1;
    *reason_out = process_wait(p);

    if (reason_out->reason == PROC_STOPPED) {
        if (reason_out->info == SIGTRAP) {
            control_rewind(c, p);
        }
    }
    return 0;
}

int64_t control_memory_read(const struct control *c, struct process *p, uint64_t address,
                            uint8_t *out, uint32_t size_bytes) {
    assert(c != NULL);
    assert(p != NULL);
    assert(out != NULL);
    assert(size_bytes > 0);

    const int64_t moved = process_memory_read(p, address, out, size_bytes);
    if (moved <= 0) return -1;
    assert(moved <= (int64_t)size_bytes);

    control_unmask(c, address, out, size_bytes);
    return moved;
}

// the 0xCC that makes the breakpoint work. So the new byte goes into the saved
// slot, and the trap byte goes straight back over it in memory.
int control_memory_write(struct control *c, struct process *p, uint64_t address,
                         const uint8_t *source, uint32_t size_bytes) {
    assert(c != NULL);
    assert(p != NULL);
    assert(source != NULL);
    assert(size_bytes > 0);
    assert(c->count <= control_breakpoints_max);

    if (process_memory_write(p, address, source, size_bytes) == -1) return -1;

    // Bounded by the breakpoint count, not by the byte count: the two are
    // unrelated, and indexing the table by size_bytes reads past the array.
    for (uint32_t i = 0; i < c->count; i++) {
        struct control_breakpoint *const breakpoint = &c->breakpoints[i];
        if (!breakpoint->enabled) continue;
        if (breakpoint->address < address) continue;

        const uint64_t offset = breakpoint->address - address;
        if (offset >= size_bytes) continue;

        breakpoint->original_byte = source[offset];
        const uint8_t trap = (uint8_t)control_int3;
        if (process_memory_write(p, breakpoint->address, &trap, 1) == -1) return -1;
    }
    return 0;
}

void control_unmask(const struct control *c, uint64_t address, uint8_t *bytes,
                    uint32_t size_bytes) {
    assert(c != NULL);
    assert(bytes != NULL);
    assert(size_bytes > 0);
    assert(c->count <= control_breakpoints_max);

    for (uint32_t i = 0; i < c->count; i++) {
        const struct control_breakpoint *const breakpoint = &c->breakpoints[i];
        if (!breakpoint->enabled) continue;

        // Guarding the low side first is not decoration: unsigned subtraction
        // below the start of the range wraps to something near 2^64, and a
        // bounds check after it would pass.
        if (breakpoint->address < address) continue;

        const uint64_t offset = breakpoint->address - address;
        if (offset >= size_bytes) continue;

        bytes[offset] = breakpoint->original_byte;
    }
}

// Syscall budget: 4 (readv for the original byte, then peek + poke to plant the
// trap, then the peek half of the read-modify-write).
// Allocation: none.
static int control_arm(struct control_breakpoint *breakpoint, struct process *p) {
    assert(breakpoint != NULL);
    assert(p != NULL);
    assert(!breakpoint->enabled);

    // Read before write. The other order saves 0xCC as the program's byte, and
    // the tracee then traps forever at the same address.
    uint8_t original = 0;
    if (process_memory_read(p, breakpoint->address, &original, 1) != 1) return -1;
    assert(original != control_int3);  // Double-arming would overwrite the saved byte.

    const uint8_t trap = (uint8_t)control_int3;
    if (process_memory_write(p, breakpoint->address, &trap, 1) == -1) return -1;

    breakpoint->original_byte = original;
    breakpoint->enabled = true;
    return 0;
}

// Syscall budget: 2 (peek + poke).
// Allocation: none.
static int control_disarm(struct control_breakpoint *breakpoint, struct process *p) {
    assert(breakpoint != NULL);
    assert(p != NULL);
    assert(breakpoint->enabled);

    if (process_memory_write(p, breakpoint->address, &breakpoint->original_byte, 1) == -1) {
        return -1;
    }
    breakpoint->enabled = false;
    return 0;
}

// Syscall budget: 8 (2 disarm, 1 SINGLESTEP, 1 waitpid, 4 re-arm).
// Allocation: none.
static int control_step_over(struct control_breakpoint *breakpoint, struct process *p,
                             struct stop_reason *reason_out) {
    assert(breakpoint != NULL);
    assert(p != NULL);
    assert(reason_out != NULL);
    assert(breakpoint->enabled);

    if (control_disarm(breakpoint, p) == -1) return -1;
    if (process_step(p) == -1) return -1;
    *reason_out = process_wait(p);

    // Re-arm whenever there is still a tracee to write to. Skipping the re-arm
    // on a live process loses the breakpoint silently after its first hit.
    if (process_gone(p)) return 0;
    return control_arm(breakpoint, p);
}

static void control_rewind(struct control *c, struct process *p) {
    assert(c != NULL);
    assert(p != NULL);

    const struct user_regs_struct *const registers = process_registers(p);
    if (registers == NULL) return;

    // Nothing executes at address 0, and rip - 1 there would wrap to 2^64 - 1.
    if (registers->rip == 0) return;

    const uint64_t hit = registers->rip - 1;
    const struct control_breakpoint *const breakpoint = control_find_by_address(c, hit);
    if (breakpoint == NULL) return;
    if (!breakpoint->enabled) return;

    struct user_regs_struct block = *registers;
    block.rip = hit;
    if (process_registers_set(p, &block) == -1) {
        fprintf(stderr, "could not rewind rip onto the breakpoint\n");
    }
}

static struct control_breakpoint *control_find_by_id(struct control *c, uint32_t id) {
    assert(c != NULL);
    assert(c->count <= control_breakpoints_max);

    for (uint32_t index = 0; index < c->count; index++) {
        if (c->breakpoints[index].id == id) return &c->breakpoints[index];
    }
    return NULL;
}

// Upgrade trigger: raise control_breakpoints_max above 64, or start calling
// this per instruction rather than per stop. Either one makes the sorted
// uint64_t array and a binary search the right shape.
static struct control_breakpoint *control_find_by_address(struct control *c, uint64_t address) {
    assert(c != NULL);
    assert(c->count <= control_breakpoints_max);

    for (uint32_t index = 0; index < c->count; index++) {
        if (c->breakpoints[index].address == address) return &c->breakpoints[index];
    }
    return NULL;
}
