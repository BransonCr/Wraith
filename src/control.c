// Wraith's run-control layer. It owns the one trick that makes a debugger a
// debugger: swap the first byte of an instruction for 0xCC, let the CPU fault
// into the kernel, and catch the SIGTRAP the kernel sends the tracer.
//
// This layer knows what a breakpoint is. The layer below it knows only bytes
// and addresses, and this file is the only place that turns one into the other.
#include <control.h>

#include <assert.h>
#include <inttypes.h> // PRIx64
#include <signal.h>   // SIGTRAP
#include <stdio.h>    // fprintf

// Helpers, declared up front so a reader meets the entry points first.
static struct control_breakpoint *control_find_by_id(struct control *c,
                                                     uint32_t id);
static struct control_breakpoint *control_find_by_address(struct control *c,
                                                          uint64_t address);
static int control_arm(struct control_breakpoint *breakpoint,
                       struct process *p);
static int control_disarm(struct control_breakpoint *breakpoint,
                          struct process *p);
static int control_step_over(struct control_breakpoint *breakpoint,
                             struct process *p, struct stop_reason *reason_out);
static void control_rewind(struct control *c, struct process *p);

void control_init(struct control *c) {
  assert(c != NULL);

  *c = (struct control){
      .count = 0,
      .id_next = 1,
  };
}

int control_breakpoint_set(struct process *p, struct control *c,
                           uint64_t address, uint32_t *id_out) {
  assert(p != NULL);
  assert(c != NULL);
  assert(id_out != NULL);
  assert(c->count < control_breakpoints_max);

  if (c->count == control_breakpoints_max) {
    fprintf(stderr, "breakpoint table is full (%d max)\n",
            control_breakpoints_max);
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
      .enabled = true,
  };

  if (control_arm(breakpoint, p) == -1)
    return -1;

  *id_out = breakpoint->id;
  c->count++;
  c->id_next++;
  return 0;
}

int control_breakpoint_enable(struct control *c, struct process *p,
                              uint32_t id) {
  assert(p->pid > 0);
  assert(c != NULL);

  struct control_breakpoint *breakpoint = control_find_by_id(c, id);
  if (breakpoint == NULL) {
    fprintf(stderr, "breakpoint %d does not exist\n", id);
    return -1;
  }

  if (breakpoint->enabled)
    return 0; // already enabled
  return control_arm(breakpoint, p);
}

int control_breakpoint_delete(struct control *c, struct process *p,
                              uint32_t id) {
  assert(p->pid > 0);
  assert(c != NULL);
  assert(c->count <= control_breakpoints_max);

  struct control_breakpoint *breakpoint = control_find_by_id(c, id);
  if (breakpoint == NULL) {
    fprintf(stderr, "no breakpoint with id %u\n", id);
    return -1;
  }

  // put the programs own byte back before forgetting where went
  if (breakpoint->enabled) {
    if (control_disarm(breakpoint, p) == -1)
      return -1;
  }

  // Shift the tail down rather than swapping the last row in so 'list' keeps
  //  its id order and a user reading it twice ses the same thing twice.
  //  gotta come back to this one
  const uint32_t position = (uint32_t)(breakpoint - c->breakpoints);
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
const struct control_breakpoint *control_breakpoint_at(const struct control *c,
                                                       uint32_t index) {
  assert(c != NULL);
  assert(index < c->count);

  return &c->breakpoints[index];
}

int control_continue(struct control *c, struct process *p,
                     struct stop_reason *reason_out) {
  assert(p != NULL);
  assert(c != NULL);
  assert(reason_out != NULL);

  const struct user_regs_struct *registers = process_registers(p);
  if (registers == NULL)
    return -1;

  // pass the RIP register which is the address of the next instruction
  struct control_breakpoint *const here =
      control_find_by_address(c, registers->rip);
  if (here != NULL && here->enabled) {
    if (control_step_over(here, p, reason_out) == -1)
      return -1;
    if (reason_out->reason == PROC_STOPPED)
      return 0;
  }

  if (process_resume(p) == -1)
    return -1;
  *reason_out = process_wait(p);
  if (reason_out->reason == PROC_STOPPED) {
    if (reason_out->info == SIGTRAP) {
      control_rewind(c, p);
    }
  }
  return 0; // YAYAYYA
}
int64_t control_memory_read(const struct control *c, struct process *p,
                            uint64_t address, uint8_t *out,
                            uint32_t size_bytes) {
  assert(p != NULL);
  assert(c != NULL);
  assert(out != NULL);
  assert(size_bytes > 0);

  const int64_t moved = process_memory_read(p, address, out, size_bytes);
  if (moved <= 0)
    return -1;

  control_unmask(c, address, out, size_bytes);
  return moved;
}

// The mirror of the read filter. A write landing on an armed breakpoint must
// change what the program will execute once the breakpoint is gone, not erase
// the 0xCC that makes the breakpoint work. So the new byte goes into the saved
// slot, and the trap byte goes straight back over it in memory.
int control_memory_write(struct control *c, struct process *p, uint64_t address,
                         const uint8_t *source, uint32_t size_bytes) {
  assert(p != NULL);
  assert(c != NULL);
  assert(source != NULL);
  assert(size_bytes > 0);

  if (process_memory_write(p, address, source, size_bytes) == -1)
    return -1;

  for (uint32_t i = 0; i < size_bytes; i++) {
    struct control_breakpoint *const breakpoint = &c->breakpoints[i];
    if (!breakpoint->enabled)
      continue;
    if (breakpoint->address < address)
      continue;

    const uint64_t offset = breakpoint->address - address;
    if (offset >= size_bytes)
      continue;

    breakpoint->original_byte = source[offset];
    const uint8_t trap = (uint8_t)control_int3;
    if (process_memory_write(p, breakpoint->address, &trap, 1) == -1)
      return -1;
  }
  return 0;
}

void control_unmask(const struct control *c, uint64_t address, uint8_t *bytes,
                    uint32_t size_bytes) {
  assert(c != NULL);
  assert(bytes != NULL);
  assert(c->count <= control_breakpoints_max);

  for (uint32_t i = 0; i < c->count; i++) {
    const struct control_breakpoint *const breakpoint = &c->breakpoints[i];
    if (!breakpoint->enabled)
      continue;

    // guarding low side first is not declaration: unsiged substraction
    // below the start of the range wraps to something near 2^64, and bounds
    // check after it would pass
    if (breakpoint->address < address)
      continue;

    const uint64_t offset = breakpoint->address - address;
    if (offset >= size_bytes)
      continue;

    bytes[offset] = breakpoint->original_byte;
  }
}

// Syscall budget: 3 (readv, then peek + poke for the partial word).
static int control_arm(struct control_breakpoint *breakpoint,
                       struct process *p) {
  assert(breakpoint != NULL);
  assert(p != NULL);
  assert(breakpoint->enabled);
  const uint8_t trap = (uint8_t)control_int3;
  if (process_memory_write(p, breakpoint->address,&trap, 1) == -1)
    return -1;

  breakpoint->enabled = false;
  return 0;
}
// Syscall budget: 2 (peek + poke).
static int control_disarm(struct control_breakpoint *breakpoint,
                          struct process *p) {
  assert(breakpoint != NULL);
  assert(p != NULL);
  assert(breakpoint->enabled);

  if (process_memory_write(p, breakpoint->address, &breakpoint->original_byte,
                           1) == -1) {
    return -1;
  }
  breakpoint->enabled = false;
  return 0;
}

// Syscall budget: 7 (2 disarm, 1 SINGLESTEP, 1 waitpid, 3 re-arm).
static int control_step_over(struct control_breakpoint *breakpoint,
                             struct process *p,
                             struct stop_reason *reason_out) {
  assert(breakpoint != NULL);
  assert(p != NULL);
  assert(reason_out != NULL);
  assert(breakpoint->enabled);

  if (control_disarm(breakpoint, p) == -1)
    return -1;
  if (process_step(p) == -1)
    return -1;
  *reason_out = process_wait(p);

  if (reason_out->reason == PROC_STOPPED)
    return 0;

  return control_arm(breakpoint, p);
}

// A trap leaves rip one byte past the 0xCC, because int3 is a trap and not a
// fault: the CPU saves the address of the NEXT instruction, the one after the
// byte that just ran. Undo that here, so no layer above ever learns the tax
// exists.
//
// si_code cannot make this decision. On this kernel an int3 reports SI_KERNEL
// (128), not TRAP_BRKPT (1) — measured. So ask a question that does have an
// exact answer: is the byte we just ran off the end of one of ours?
static void control_rewind(struct control *c, struct process *p) {
  assert(c != NULL);
  assert(p != NULL);

  const struct user_regs_struct *registers = process_registers(p);
  if (registers == NULL)
    return;
  if (registers->rip == 0)
    return; // edge case nothing executes at -1 blud bomba
            //
  const uint64_t hit = registers->rip - 1;
  const struct control_breakpoint *const breakpoint =
      control_find_by_address(c, hit);
  if (breakpoint == NULL)
    return;
  if (!breakpoint->enabled)
    return;

  struct user_regs_struct block = *registers;
  block.rip = hit;
  if (process_registers_set(p, &block) == -1) {
    fprintf(stderr, "Count not rewind rip onto the breakpoint\n");
  }
}

static struct control_breakpoint *control_find_by_id(struct control *c,
                                                     uint32_t id) {
  assert(c != NULL);
  assert(c->count <= control_breakpoints_max);

  for (uint32_t i = 0; i < c->count; i++) {
    if (c->breakpoints[i].id == id)
      return &c->breakpoints[i];
  }
  return NULL; // not found
}

// A linear scan, not the sorted parallel address array
static struct control_breakpoint *control_find_by_address(struct control *c,
                                                          uint64_t address) {
  assert(c != NULL);
  assert(c->count <= control_breakpoints_max);

  for (uint32_t index = 0; index < c->count; index++) {
    if (c->breakpoints[index].address == address)
      return &c->breakpoints[index];
  }
  return NULL;
}
