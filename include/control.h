#ifndef WRAITH_CONTROL_H_
#define WRAITH_CONTROL_H_

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

#include <process.h>


enum {control_int3 = 0xCC};

enum {control_breakpoints_max = 64};

struct control_breakpoint {
    uint64_t address;
    uint32_t id;
    uint8_t original_byte;
    bool enabled;
};

static_assert(sizeof(struct control_breakpoint) == 16,
                "four breakpoints per cache line");

struct control {
    struct control_breakpoint breakpoints[control_breakpoints_max];
    uint32_t count;
    uint32_t id_next;
};


int control_breakpoint_set(struct process *p, struct control *c, uint64_t address,
                            uint32_t *out);
int control_breakpoint_enable(struct control *c, struct process *p, uint32_t id);
int control_breakpoint_disable(struct control *c, struct process *p, uint32_t id);
int control_breakpoint_delete(struct control *c, struct process *p, uint32_t id);

uint32_t control_breakpoints_count(const struct control *c);
const struct control_breakpoint *control_breakpoint_at(const struct control *c, uint32_t index);

// Steps one instruction, moving the trap byte out of the way first if rip is
// sitting on one — same reason as control_continue: a 0xCC under rip means the
// step executes the trap rather than the instruction it replaced.
int control_step(struct control *c, struct process *p, struct stop_reason *reason_out);// blocks until the tracee stops again. Returns 0 and fills *reason_out on a


// One call rather than a resume/wait pair, because the step-over in the middle
// already consumes a stop: a caller pairing its own resume and wait around this
// would count that stop twice and then block forever on a tracee that is not
// going to stop again.
// Syscall budget: 1 when no breakpoint is under rip, 7 when one is.
// Allocation: none.
int control_continue(struct control *c, struct process *p,
                     struct stop_reason *reason_out);

// Reads tracee memory with every armed 0xCC painted back over with the byte it
// replaced, so the caller sees the program the user wrote rather than the
// program wraith edited.
// Syscall budget: same as process_memory_read.
// Allocation: none.
int64_t control_memory_read(const struct control *c, struct process *p,
                            uint64_t address, uint8_t *out, uint32_t size_bytes);

// Writes tracee memory, keeping armed breakpoints armed: a byte landing on a
// breakpoint updates the saved original rather than erasing the trap.
// Syscall budget: process_memory_write, plus 2 per breakpoint in the range.
// Allocation: none.
int control_memory_write(struct control *c, struct process *p,
                         uint64_t address, const uint8_t *source,
                         uint32_t size_bytes);

// Pure: paints saved bytes over a buffer already read out of the tracee. No
// process, no syscalls, so the interesting half of the memory path is testable
// without a live tracee.
void control_unmask(const struct control *c, uint64_t address,
                    uint8_t *bytes, uint32_t size_bytes);

#endif  // WRAITH_CONTROL_H_
