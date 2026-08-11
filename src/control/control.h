#ifndef WRAITH_CONTROL_H_
#define WRAITH_CONTROL_H_

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

#include <process/process.h>


enum {control_int3 = 0xCC};

enum {control_breakpoints_max = 64};
enum { control_syscalls_max = 16 };

// Which kernel crossings stop the program. NONE is the default and stays the
// default: PTRACE_SYSCALL costs two stops per syscall, which is the 15x class
// of slowdown applied to the whole program rather than to one address.
enum control_catch {
    CONTROL_CATCH_NONE,
    CONTROL_CATCH_SOME,
    CONTROL_CATCH_ALL,
};

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
    // INVARIANT: meaningful only when catch_mode == CONTROL_CATCH_SOME.
    // INVARIANT: syscalls_count <= control_syscalls_max.
    uint16_t syscalls[control_syscalls_max];
    uint32_t count;
    uint32_t id_next;
    uint32_t syscalls_count;
    enum control_catch catch_mode;
    // The tracee's own signal, held from the stop that caught it until the next
    // resume hands it back. 0 means nothing owed.
    uint8_t signal_pending;
};

void control_init(struct control *c);
int control_breakpoint_set(struct control *c, struct process *p,
                           uint64_t address, uint32_t *id_out);
int control_breakpoint_enable(struct control *c, struct process *p, uint32_t id);
int control_breakpoint_disable(struct control *c, struct process *p, uint32_t id);
int control_breakpoint_delete(struct control *c, struct process *p, uint32_t id);
int control_catch_syscalls(struct control *c, enum control_catch mode,
                            const uint16_t *numbers, uint32_t count);
uint32_t control_breakpoints_count(const struct control *c);
const struct control_breakpoint *control_breakpoint_at(const struct control *c, uint32_t index);

int control_step(struct control *c, struct process *p, struct stop_reason *reason_out);// blocks until the tracee stops again. Returns 0 and fills *reason_out on a


int control_continue(struct control *c, struct process *p,
                     struct stop_reason *reason_out);
//Runs to an address and then stops there. Reports own trap as a step.
int control_run_to(struct control *c, struct process *p, uint64_t address,
                    struct stop_reason *result_out);

int64_t control_memory_read(const struct control *c, struct process *p,
                            uint64_t address, uint8_t *out, uint32_t size_bytes);

int control_memory_write(struct control *c, struct process *p,
                         uint64_t address, const uint8_t *source,
                         uint32_t size_bytes);

void control_unmask(const struct control *c, uint64_t address,
                    uint8_t *bytes, uint32_t size_bytes);

#endif  // WRAITH_CONTROL_H_
