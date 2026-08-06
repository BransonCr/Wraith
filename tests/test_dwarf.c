// Goal: prove the DWARF reader lands on exactly the right bytes, which is the
// only property that matters, because every way of getting it wrong is silent.
//
// Method: three layers. First the LEB128 and cursor primitives against bytes
// written out by hand, since every higher test is meaningless if these drift.
// Then ./target, one compilation unit, checked against readelf's own numbers.
// Then ./target_multi, two units with two abbreviation tables whose codes mean
// different tags, which is the only fixture that catches a shared-table cache.
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "arena/arena.h"
#include "dwarf/dwarf.h"
#include "dwarf/dwarf_internal.h"
#include "elf/elf.h"

enum { test_arena_bytes = 64u * 1024u * 1024u };

// Addresses from `nm target` and `readelf --debug-dump=info target`. The binary
// is -no-pie so these survive across runs.
enum {
    target_handler_low = 0x401186,
    target_handler_high = 0x401186 + 0x14,
    target_main_low = 0x40119a,
    target_main_high = 0x40119a + 0x75,
};

enum {
    multi_main_low = 0x401116,
    multi_other_low = 0x401126,
};

static void test_leb128(void) {
    // Single byte, the common case: DWARF uses LEB128 because most numbers are
    // small and cost one byte.
    const uint8_t one[] = { 0x7f };
    struct dwarf_cursor c = { .data = one, .size_bytes = sizeof one };
    assert(dwarf_cursor_uleb128(&c) == 0x7f);
    assert(c.offset == 1);
    assert(!c.overrun);

    // Multi-byte: 624485, the example in the DWARF spec itself.
    const uint8_t many[] = { 0xe5, 0x8e, 0x26 };
    c = (struct dwarf_cursor){ .data = many, .size_bytes = sizeof many };
    assert(dwarf_cursor_uleb128(&c) == 624485);
    assert(c.offset == 3);

    // Negative signed, where a missing sign extension is silent and total.
    const uint8_t negative[] = { 0x7f };
    c = (struct dwarf_cursor){ .data = negative, .size_bytes = sizeof negative };
    assert(dwarf_cursor_sleb128(&c) == -1);

    const uint8_t negative_many[] = { 0x9b, 0xf1, 0x59 };
    c = (struct dwarf_cursor){ .data = negative_many, .size_bytes = sizeof negative_many };
    assert(dwarf_cursor_sleb128(&c) == -624485);

    printf("  leb128 ok\n");
}

static void test_cursor_bounds(void) {
    const uint8_t bytes[] = { 0x01, 0x02 };
    struct dwarf_cursor c = { .data = bytes, .size_bytes = sizeof bytes };

    assert(dwarf_cursor_fixed(&c, 2) == 0x0201);
    assert(!c.overrun);

    // Past the end yields zero and sets the flag rather than reading on.
    assert(dwarf_cursor_fixed(&c, 1) == 0);
    assert(c.overrun);
    assert(c.offset == c.size_bytes);

    // The flag is sticky, which is what lets a parse function do twenty reads
    // and check for failure exactly once.
    c.offset = 0;
    assert(dwarf_cursor_fixed(&c, 1) == 0x01);
    assert(c.overrun);

    // A string with no terminator inside the section is a read off the end.
    const uint8_t unterminated[] = { 'a', 'b' };
    c = (struct dwarf_cursor){ .data = unterminated, .size_bytes = sizeof unterminated };
    assert(dwarf_cursor_string(&c) == NULL);
    assert(c.overrun);

    printf("  cursor bounds ok\n");
}

static void test_target_units(struct dwarf *d) {
    // readelf reports one unit at version 5. A parser written from a DWARF 4
    // tutorial reads 11 header bytes here and starts the first DIE one byte
    // early, which desynchronizes everything after it.
    assert(dwarf_has_info(d));
    assert(dwarf_units_count(d) == 1);
    printf("  target: %" PRIu32 " unit\n", dwarf_units_count(d));
}

static void test_target_by_address(struct dwarf *d) {
    struct dwarf_function_info info = {0};

    assert(dwarf_function_containing(d, target_main_low, &info));
    assert(info.name != NULL);
    assert(strcmp(info.name, "main") == 0);
    assert(info.low_pc == target_main_low);

    // main's DW_AT_high_pc is 0x75, a constant form, so it is a length. Read as
    // an address it would put main's end below every code address in the
    // program and this assertion would be the one that fails.
    assert(info.high_pc == target_main_high);

    // The last byte of main is inside main; the first byte past it is not.
    assert(dwarf_function_containing(d, target_main_high - 1, &info));
    assert(strcmp(info.name, "main") == 0);
    assert(!dwarf_function_containing(d, target_main_high, &info));

    // handler is static, and it ends exactly where main begins.
    assert(dwarf_function_containing(d, target_handler_low, &info));
    assert(strcmp(info.name, "handler") == 0);
    assert(info.high_pc == target_handler_high);
    assert(info.high_pc == target_main_low);

    printf("  target: address lookup ok\n");
}

static void test_target_by_name(struct dwarf *d) {
    struct dwarf_function_info info = {0};

    assert(dwarf_function_by_name(d, "main", &info));
    assert(info.low_pc == target_main_low);

    assert(dwarf_function_by_name(d, "handler", &info));
    assert(info.low_pc == target_handler_low);

    // printf, getpid and friends appear in this unit as DW_TAG_subprogram
    // declarations with a name and no address. Keeping them would answer here
    // with address zero instead of missing.
    assert(!dwarf_function_by_name(d, "printf", &info));
    assert(!dwarf_function_by_name(d, "nonexistent", &info));

    // A name query indexes every unit, and a unit is only marked indexed when
    // its walk finished on exactly the unit's last byte. So this one assertion
    // is the proof that the DIE walk did not drift by a single byte.
    assert(dwarf_units_indexed(d) == dwarf_units_count(d));

    printf("  target: name lookup ok, %" PRIu32 " units walked exactly\n",
           dwarf_units_indexed(d));
}

static void test_multi(struct dwarf *d) {
    // Two units, two abbreviation tables at different offsets. Verified with
    // readelf: code 3 is DW_TAG_subprogram in the first table and
    // DW_TAG_base_type in the second, and code 4 is DW_TAG_base_type in the
    // first and DW_TAG_volatile_type in the second. A parser that caches one
    // table does not crash here -- it reports base types as functions.
    assert(dwarf_units_count(d) == 2);

    struct dwarf_function_info info = {0};

    assert(dwarf_function_containing(d, multi_main_low, &info));
    assert(strcmp(info.name, "main") == 0);

    assert(dwarf_function_containing(d, multi_other_low, &info));
    assert(strcmp(info.name, "other") == 0);

    // main.c declares other() without defining it, so the name appears twice in
    // .debug_info and only once with an address. Zero here means the
    // declaration won.
    assert(dwarf_function_by_name(d, "other", &info));
    assert(info.low_pc == multi_other_low);

    assert(dwarf_function_by_name(d, "main", &info));
    assert(info.low_pc == multi_main_low);

    assert(dwarf_units_indexed(d) == 2);
    printf("  target_multi: %" PRIu32 " units, both tables read ok\n",
           dwarf_units_indexed(d));
}

static void test_binary(const char *path, void (*checks)(struct dwarf *)) {
    assert(path != NULL);
    assert(checks != NULL);

    struct elf elf;
    assert(elf_open(path, &elf) == 0);

    // .debug_info must arrive through the ELF layer's published API. A parser
    // that reached into struct elf could not be tested against a fixture file.
    const uint8_t *info = NULL;
    uint64_t info_size_bytes = 0;
    assert(elf_section_bytes(&elf, ".debug_info", &info, &info_size_bytes));
    assert(info != NULL);
    assert(info_size_bytes > 0);
    assert(!elf_section_bytes(&elf, ".debug_nonexistent", &info, &info_size_bytes));
    assert(info == NULL);

    struct arena arena;
    assert(arena_init(&arena, test_arena_bytes) == 0);

    struct dwarf dwarf;
    assert(dwarf_open(&dwarf, &elf, &arena) == 0);
    // 7.2: opening reads headers and .debug_aranges, and not one DIE.
    assert(arena.offset_bytes > 0);

    checks(&dwarf);

    arena_deinit(&arena);
    elf_close(&elf);
}

static void test_target_all(struct dwarf *d) {
    test_target_units(d);
    test_target_by_address(d);
    test_target_by_name(d);
}

int main(void) {
    test_leb128();
    test_cursor_bounds();
    test_binary("./target", test_target_all);
    test_binary("./target_multi", test_multi);

    printf("test_dwarf: all tests passed\n");
    return 0;
}
