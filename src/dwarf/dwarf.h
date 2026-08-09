#ifndef WRAITH_DWARF_DWARF_H_
#define WRAITH_DWARF_DWARF_H_

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#include "arena/arena.h"
#include "elf/elf.h"

// The spec and every tool spell these DW_TAG_, DW_AT_ and DW_FORM_. Here the
// prefix follows the layer, per CLAUDE.md, which owns naming outright. The
// system <dwarf.h> defines all nine hundred of them and ships with elfutils,
// which CLAUDE.md bans by name; these are the forty this chapter needs.

enum dwarf_tag {
    dwarf_tag_compile_unit = 0x11,
    dwarf_tag_subprogram = 0x2e,
};

enum dwarf_attribute {
    dwarf_attribute_name = 0x03,
    dwarf_attribute_stmt_list = 0x10,
    dwarf_attribute_low_pc = 0x11,
    dwarf_attribute_high_pc = 0x12,
    dwarf_attribute_comp_dir = 0x1b,
};

enum dwarf_form {
    dwarf_form_addr = 0x01,
    dwarf_form_block2 = 0x03,
    dwarf_form_block4 = 0x04,
    dwarf_form_data2 = 0x05,
    dwarf_form_data4 = 0x06,
    dwarf_form_data8 = 0x07,
    dwarf_form_string = 0x08,
    dwarf_form_block = 0x09,
    dwarf_form_block1 = 0x0a,
    dwarf_form_data1 = 0x0b,
    dwarf_form_flag = 0x0c,
    dwarf_form_sdata = 0x0d,
    dwarf_form_strp = 0x0e,
    dwarf_form_udata = 0x0f,
    dwarf_form_ref_addr = 0x10,
    dwarf_form_ref1 = 0x11,
    dwarf_form_ref2 = 0x12,
    dwarf_form_ref4 = 0x13,
    dwarf_form_ref8 = 0x14,
    dwarf_form_ref_udata = 0x15,
    dwarf_form_indirect = 0x16,
    dwarf_form_sec_offset = 0x17,
    dwarf_form_exprloc = 0x18,
    dwarf_form_flag_present = 0x19,
    dwarf_form_strx = 0x1a,
    dwarf_form_addrx = 0x1b,
    dwarf_form_ref_sup4 = 0x1c,
    dwarf_form_strp_sup = 0x1d,
    dwarf_form_data16 = 0x1e,
    dwarf_form_line_strp = 0x1f,
    dwarf_form_ref_sig8 = 0x20,
    dwarf_form_implicit_const = 0x21,
    dwarf_form_loclistx = 0x22,
    dwarf_form_rnglistx = 0x23,
    dwarf_form_ref_sup8 = 0x24,
    dwarf_form_strx1 = 0x25,
    dwarf_form_strx2 = 0x26,
    dwarf_form_strx3 = 0x27,
    dwarf_form_strx4 = 0x28,
    dwarf_form_addrx1 = 0x29,
    dwarf_form_addrx2 = 0x2a,
    dwarf_form_addrx3 = 0x2b,
    dwarf_form_addrx4 = 0x2c,
};

// A 32-bit reference costs half of a pointer, which doubles how many fit in a
// 64-byte cache line whether or not you use the rest of it. PERFORMANCE.md 4.2.
typedef uint32_t dwarf_strid;
typedef uint32_t dwarf_unit_id;

enum dwarf_string_section {
    dwarf_string_section_none = 0,
    dwarf_string_section_str = 1,
    dwarf_string_section_line_str = 2,
    dwarf_string_section_info = 3,
    dwarf_string_section_line = 4,
};

// Five sections need three bits, which leaves 512 MiB of offset per section.
enum {
    dwarf_strid_none = 0,
    dwarf_strid_offset_bits = 29,
    dwarf_strid_offset_max = (1u << dwarf_strid_offset_bits) - 1,
};

enum dwarf_unit_state {
    dwarf_unit_state_scanned = 0,      // Header read, not one DIE touched.
    dwarf_unit_state_indexed = 1,      // Walked, functions harvested.
    dwarf_unit_state_unsupported = 2,  // DWARF64, a unit type, or a bad walk.
};

// INVARIANT: die_offset is wherever the header parse stopped, never a constant.
// INVARIANT: functions_first .. functions_first + functions_count index dwarf::functions.
// INVARIANT: functions_count is zero until state is dwarf_unit_state_indexed.
struct dwarf_unit {
    uint32_t offset;
    uint32_t length_bytes;
    uint32_t die_offset;
    uint32_t abbrev_offset;
    uint32_t functions_first;
    uint32_t functions_count;
    uint16_t version;
    uint8_t address_size;
    uint8_t state;
    bool has_range;
};

static_assert(sizeof(struct dwarf_unit) == 32, "two units per cache line");

// A hit reads every field, so these stay together as one struct while the
// searched ranges below are split apart. PERFORMANCE.md 4.4, opposite answers.
struct dwarf_function {
    uint64_t low_pc;   // File address.
    uint64_t high_pc;  // File address, exclusive, already absolute.
    dwarf_strid name;
    dwarf_unit_id unit;
};

static_assert(sizeof(struct dwarf_function) == 24, "no padding between the pairs");

struct dwarf_name_slot {
    uint32_t hash;
    uint32_t function;
};

static_assert(sizeof(struct dwarf_name_slot) == 8, "eight slots per cache line");

struct dwarf_section {
    const uint8_t *data;  // NULL when the section is absent.
    uint64_t size_bytes;
};

struct dwarf_function_info {
    const char *name;  // NULL when the DIE carried no resolvable name.
    uint64_t low_pc;
    uint64_t high_pc;
};

enum dwarf_line_state {
    dwarf_line_state_unread = 0,
    dwarf_line_state_ready = 1,
    dwarf_line_state_unsupported = 2,
};

enum dwarf_line_flag {
    dwarf_line_flag_statement = 1u << 0,
    dwarf_line_flag_end_sequence = 1u << 1,
    dwarf_line_flag_prologue_end = 1u << 2,
};

// INVARIANT: sorted by address ascending, an end-of-sequence row first on a tie.
struct dwarf_line_row {
    uint64_t address;  // File address.
    uint32_t line;
    uint16_t file;     // Index into dwarf_line_table::files.
    uint16_t flags;
};

static_assert(sizeof(struct dwarf_line_row) == 16, "four rows per cache line");

struct dwarf_line_file {
    dwarf_strid directory;
    dwarf_strid name;
};

static_assert(sizeof(struct dwarf_line_file) == 8, "eight names per cache line");

// INVARIANT: rows and files are set only once state is dwarf_line_state_ready.
struct dwarf_line_table {
    struct dwarf_line_row *rows;
    struct dwarf_line_file *files;
    uint32_t rows_count;
    uint32_t files_count;
    uint8_t state;
};

static_assert(sizeof(struct dwarf_line_table) == 32, "two tables per cache line");

struct dwarf_line_info {
    const char *directory;  // NULL when the entry named no directory.
    const char *file;       // NULL when the path did not resolve.
    uint64_t address;       // File address of the row, at or below the query.
    uint32_t line;
};

// INVARIANT: range_low is sorted ascending; range_high and range_unit are parallel.
// INVARIANT: ranges_count <= ranges_capacity, both fixed after dwarf_open.
// INVARIANT: every pointer aims into the arena or into the elf mapping; nothing is owned.
struct dwarf {
    const struct elf *elf;
    struct arena *arena;

    struct dwarf_section info;
    struct dwarf_section abbrev;
    struct dwarf_section str;
    struct dwarf_section line_str;
    struct dwarf_section line;
    struct dwarf_section aranges;

    struct dwarf_unit *units;
    uint64_t *range_low;
    uint64_t *range_high;
    uint32_t *range_unit;
    struct dwarf_function *functions;
    struct dwarf_name_slot *names;
    struct dwarf_line_table *lines;  // One per unit, NULL until the first query.

    uint32_t units_count;
    uint32_t ranges_count;
    uint32_t ranges_capacity;
    uint32_t functions_count;
    uint32_t functions_capacity;
    uint32_t names_capacity;

    bool ranges_resolved;
    bool names_built;
};

int dwarf_open(struct dwarf *d, const struct elf *e, struct arena *arena);

bool dwarf_has_info(const struct dwarf *d);
uint32_t dwarf_units_count(const struct dwarf *d);

uint32_t dwarf_units_indexed(const struct dwarf *d);

bool dwarf_function_containing(struct dwarf *d, uint64_t address_file,
                               struct dwarf_function_info *out);
bool dwarf_function_by_name(struct dwarf *d, const char *name,
                            struct dwarf_function_info *out);

// Syscall budget: 0.
// Allocation: module arena, on the first query against a unit. No malloc.
bool dwarf_line_at_address(struct dwarf *d, uint64_t address_file,
                           struct dwarf_line_info *out);
uint32_t dwarf_line_addresses(struct dwarf *d, const char *path, uint32_t line,
                              uint64_t *out, uint32_t count_max);
uint32_t dwarf_lines_decoded(const struct dwarf *d);

const char *dwarf_string(const struct dwarf *d, dwarf_strid id);

#endif  // WRAITH_DWARF_DWARF_H_
