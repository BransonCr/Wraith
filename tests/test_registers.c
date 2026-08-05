#include <registers/registers.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void test_table_invariants(void) {
    for (uint32_t index = 0; index < WRAITH_REGISTER_COUNT; index++) {
        const struct register_info *const row = &register_table[index];
        assert(row->name != NULL);
        assert(row->name[0] != '\0');
        assert(row->size_bytes == 8);
        assert(row->area == REGISTER_AREA_GENERAL);
        assert(row->dwarf_id != WRAITH_REGISTER_DWARF_NONE);
        assert((size_t)row->offset_bytes + row->size_bytes <= sizeof(struct user_regs_struct));
    }
}

// Both uniqueness invariants the header declares. O(n squared) over 18 rows is
// 153 comparisons at build time, which is free and needs no sorting.
static void test_names_and_dwarf_ids_unique(void) {
    for (uint32_t outer = 0; outer < WRAITH_REGISTER_COUNT; outer++) {
        for (uint32_t inner = outer + 1; inner < WRAITH_REGISTER_COUNT; inner++) {
            assert(register_table[outer].dwarf_id != register_table[inner].dwarf_id);
            assert(strcmp(register_table[outer].name, register_table[inner].name) != 0);
        }
    }
}

// The three DWARF numbers most likely to be wrong, pinned by hand. rdx and rcx
// are the pair everyone transposes; eflags sits at 49, far from its neighbours.
static void test_dwarf_numbering_spot_checks(void) {
    assert(register_by_name("rax")->dwarf_id == 0);
    assert(register_by_name("rdx")->dwarf_id == 1);
    assert(register_by_name("rcx")->dwarf_id == 2);
    assert(register_by_name("rip")->dwarf_id == 16);
    assert(register_by_name("eflags")->dwarf_id == 49);

    // The two lookups must agree, in both directions, for every row.
    for (uint32_t index = 0; index < WRAITH_REGISTER_COUNT; index++) {
        const struct register_info *const row = &register_table[index];
        assert(register_by_name(row->name) == row);
        assert(register_by_dwarf_id(row->dwarf_id) == row);
    }
}

// The negative space: a word that names no register must miss, not crash and
// not return row zero.
static void test_lookup_misses(void) {
    assert(register_by_name("rex") == NULL);
    assert(register_by_name("RAX") == NULL);  // Lookup is case-sensitive today.
    assert(register_by_dwarf_id(200) == NULL);
}

static void test_read_write_round_trip(void) {
    struct user_regs_struct block;
    memset(&block, 0, sizeof block);

    const struct register_info *const rax = register_by_name("rax");
    assert(rax != NULL);

    register_write(&block, rax, 0xDEADBEEFCAFEF00DULL);
    assert(block.rax == 0xDEADBEEFCAFEF00DULL);  // Paired: check the field directly.

    struct register_value value;
    register_read(&block, rax, &value);
    assert(value.integer == 0xDEADBEEFCAFEF00DULL);
    assert(value.size_bytes == 8);
    assert(value.format == REGISTER_FORMAT_INTEGER);
}

// The test that actually earns its keep: prove every row's window is where the
// row says it is. A wrong offsetof passes every test above and fails this one.
static void test_each_row_writes_its_own_window(void) {
    for (uint32_t index = 0; index < WRAITH_REGISTER_COUNT; index++) {
        struct user_regs_struct block;
        memset(&block, 0, sizeof block);
        register_write(&block, &register_table[index], UINT64_MAX);

        const uint32_t offset_bytes = register_table[index].offset_bytes;
        const uint32_t offset_end = offset_bytes + register_table[index].size_bytes;
        const uint8_t *const bytes = (const uint8_t *)&block;

        for (uint32_t byte = 0; byte < sizeof block; byte++) {
            if (byte < offset_bytes) {
                assert(bytes[byte] == 0x00);
            } else {
                if (byte < offset_end) {
                    assert(bytes[byte] == 0xFF);
                } else {
                    assert(bytes[byte] == 0x00);
                }
            }
        }
    }
}

int main(void) {
    test_table_invariants();
    test_names_and_dwarf_ids_unique();
    test_dwarf_numbering_spot_checks();
    test_lookup_misses();
    test_read_write_round_trip();
    test_each_row_writes_its_own_window();

    printf("test_registers: all tests passed\n");
    return 0;
}
