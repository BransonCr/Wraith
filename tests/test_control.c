// Chapter 7/8 — automated tests for the control module.
// No framework (no-libs rule): plain assert. A failed assert prints file:line
// and aborts; reaching the end means everything passed.
//
// Split in two halves on purpose. control_unmask is pure, so the interesting
// logic runs with no tracee at all. The round trips below it need a real
// process, and take their address from wherever the tracee happens to be
// stopped rather than hardcoding one, so they survive ASLR and a new libc.
#include <control/control.h>
#include <process/process.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// Placed by hand rather than through control_breakpoint_set, because the whole
// point of the pure entry point is that it needs no process to talk to.
static void breakpoint_place(struct control *c, uint64_t address,
                             uint8_t original_byte, bool enabled) {
    assert(c != NULL);
    assert(c->count < control_breakpoints_max);

    c->breakpoints[c->count] = (struct control_breakpoint){
        .address = address,
        .id = c->id_next,
        .original_byte = original_byte,
        .enabled = enabled,
    };
    c->count++;
    c->id_next++;
}

static void test_unmask_paints_only_enabled_breakpoints(void) {
    struct control c;
    control_init(&c);
    breakpoint_place(&c, 0x1000, 0x55, true);
    breakpoint_place(&c, 0x1003, 0x90, false);

    uint8_t bytes[8];
    memset(bytes, 0xCC, sizeof bytes);
    control_unmask(&c, 0x1000, bytes, sizeof bytes);

    assert(bytes[0] == 0x55);  // Enabled: the saved byte comes back.
    assert(bytes[3] == 0xCC);  // Disabled: wraith never wrote here, so leave it.
    for (uint32_t index = 1; index < 8; index++) {
        assert(bytes[index] == 0xCC);
    }
}

// The negative space, and the one that would be a remote write primitive if the
// guard were missing: a breakpoint BELOW the range makes address subtraction
// wrap to roughly 2^64, which sails past any bounds check written as a
// less-than on the result.
static void test_unmask_ignores_breakpoints_outside_the_range(void) {
    struct control c;
    control_init(&c);
    breakpoint_place(&c, 0x0FFF, 0xAA, true);  // One byte below.
    breakpoint_place(&c, 0x1008, 0xBB, true);  // One byte past the end.

    uint8_t bytes[8];
    memset(bytes, 0xCC, sizeof bytes);
    control_unmask(&c, 0x1000, bytes, sizeof bytes);

    for (uint32_t index = 0; index < 8; index++) {
        assert(bytes[index] == 0xCC);
    }
}

// End to end against a real tracee, proving three things in one pass: the
// tracee's memory really does hold 0xCC, the filtered read hides it, and delete
// puts the program back exactly as it was found.
static void test_breakpoint_round_trip(void) {
    struct process p;
    assert(process_launch("/bin/true", &p) == 0);
    assert(p.state == PROC_STOPPED);

    const struct user_regs_struct *const registers = process_registers(&p);
    assert(registers != NULL);
    const uint64_t address = registers->rip;

    uint8_t before = 0;
    assert(process_memory_read(&p, address, &before, 1) == 1);
    assert(before != control_int3);  // Or the test proves nothing below.

    struct control c;
    control_init(&c);

    uint32_t id = 0;
    assert(control_breakpoint_set(&c, &p, address, &id) == 0);
    assert(id == 1);
    assert(control_breakpoints_count(&c) == 1);
    assert(control_breakpoint_at(&c, 0)->original_byte == before);
    assert(control_breakpoint_at(&c, 0)->enabled);

    // The raw read sees wraith's byte...
    uint8_t raw = 0;
    assert(process_memory_read(&p, address, &raw, 1) == 1);
    assert(raw == control_int3);

    // ...and the filtered read sees the program's.
    uint8_t masked = 0;
    assert(control_memory_read(&c, &p, address, &masked, 1) == 1);
    assert(masked == before);

    assert(control_breakpoint_delete(&c, &p, id) == 0);
    assert(control_breakpoints_count(&c) == 0);

    uint8_t after = 0;
    assert(process_memory_read(&p, address, &after, 1) == 1);
    assert(after == before);

    process_detach(&p);
}

static void test_breakpoint_set_rejects_duplicates_and_bad_ids(void) {
    struct process p;
    assert(process_launch("/bin/true", &p) == 0);

    const struct user_regs_struct *const registers = process_registers(&p);
    assert(registers != NULL);

    struct control c;
    control_init(&c);

    uint32_t first = 0;
    assert(control_breakpoint_set(&c, &p, registers->rip, &first) == 0);

    uint32_t second = 0;
    assert(control_breakpoint_set(&c, &p, registers->rip, &second) == -1);
    assert(control_breakpoints_count(&c) == 1);

    assert(control_breakpoint_enable(&c, &p, 999) == -1);
    assert(control_breakpoint_delete(&c, &p, 999) == -1);
    assert(control_breakpoints_count(&c) == 1);

    process_detach(&p);
}

// Writes that do not begin or end on a word boundary are the case POKEDATA
// cannot express directly, so they are the case worth testing. The stack is
// read-write, which keeps this test about word patching rather than FOLL_FORCE.
static void test_memory_write_patches_partial_words(void) {
    struct process p;
    assert(process_launch("/bin/true", &p) == 0);

    const struct user_regs_struct *const registers = process_registers(&p);
    assert(registers != NULL);
    const uint64_t scratch = registers->rsp - 256;  // Stack nobody is using.

    uint8_t zeroes[16];
    memset(zeroes, 0, sizeof zeroes);
    assert(process_memory_write(&p, scratch, zeroes, sizeof zeroes) == 0);

    // Three bytes at offset 1: inside one word, touching neither end.
    const uint8_t inside[3] = {0xDE, 0xAD, 0xBE};
    assert(process_memory_write(&p, scratch + 1, inside, 3) == 0);

    // Three bytes at offset 7: straddles the boundary between two words.
    const uint8_t across[3] = {0x11, 0x22, 0x33};
    assert(process_memory_write(&p, scratch + 7, across, 3) == 0);

    uint8_t readback[16];
    assert(process_memory_read(&p, scratch, readback, sizeof readback) == 16);

    assert(readback[0] == 0x00);  // Untouched neighbour before.
    assert(readback[1] == 0xDE);
    assert(readback[2] == 0xAD);
    assert(readback[3] == 0xBE);
    assert(readback[4] == 0x00);  // Untouched neighbour after.
    assert(readback[7] == 0x11);
    assert(readback[8] == 0x22);  // Second word.
    assert(readback[9] == 0x33);
    assert(readback[10] == 0x00);

    process_detach(&p);
}

int main(void) {
    test_unmask_paints_only_enabled_breakpoints();
    test_unmask_ignores_breakpoints_outside_the_range();
    test_breakpoint_round_trip();
    test_breakpoint_set_rejects_duplicates_and_bad_ids();
    test_memory_write_patches_partial_words();

    printf("test_control: all tests passed\n");
    return 0;
}
