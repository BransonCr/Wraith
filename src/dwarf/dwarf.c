#include "dwarf/dwarf.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "arena/arena.h"
#include "dwarf/dwarf_internal.h"
#include "elf/elf.h"

enum {
    // The smallest possible unit: a 4-byte length, the 8 remaining header bytes
    // of DWARF 5, and not one DIE. Nothing can be smaller, so it bounds the unit
    // count. Reserving the bound costs address space, not memory.
    dwarf_unit_bytes_min = 12,

    // A subprogram this indexer keeps carries an abbreviation code, a name
    // reference and two address attributes, so no unit holds more functions
    // than its bytes divided by this.
    dwarf_function_bytes_min = 14,

    // One .debug_aranges tuple is two addresses.
    dwarf_arange_bytes = 16,

    dwarf_abbrevs_max = 2048,
    dwarf_abbrev_attributes_max = 16384,

    dwarf_name_bytes_max = 4096,
    dwarf_binary_search_steps_max = 32,
};

enum dwarf_unit_type {
    dwarf_unit_type_compile = 0x01,
};

enum dwarf_form_class {
    dwarf_form_class_unknown = 0,
    dwarf_form_class_address,
    dwarf_form_class_constant,
    dwarf_form_class_string,
};

struct dwarf_abbrev_attribute {
    int64_t implicit_const;
    uint16_t attribute;
    uint16_t form;
};

static_assert(sizeof(struct dwarf_abbrev_attribute) == 16, "four per cache line");

struct dwarf_abbrev {
    uint32_t code;
    uint32_t attributes_first;
    uint16_t attributes_count;
    uint16_t tag;
    bool has_children;
};

static_assert(sizeof(struct dwarf_abbrev) == 16, "four per cache line");

struct dwarf_abbrev_table {
    const struct dwarf_abbrev *abbrevs;
    const struct dwarf_abbrev_attribute *attributes;
    uint32_t count;
};

struct dwarf_die_values {
    uint64_t low_pc;
    uint64_t high_pc_raw;
    dwarf_strid name;
    bool has_low_pc;
    bool has_high_pc;
    bool high_pc_is_length;
};

static struct dwarf_abbrev dwarf_abbrev_pool[dwarf_abbrevs_max];
static struct dwarf_abbrev_attribute dwarf_abbrev_attribute_pool[dwarf_abbrev_attributes_max];

static const uint8_t dwarf_form_width[] = {
    [dwarf_form_data2] = 2,     [dwarf_form_data4] = 4,     [dwarf_form_data8] = 8,
    [dwarf_form_data1] = 1,     [dwarf_form_flag] = 1,      [dwarf_form_strp] = 4,
    [dwarf_form_ref_addr] = 4,  [dwarf_form_ref1] = 1,      [dwarf_form_ref2] = 2,
    [dwarf_form_ref4] = 4,      [dwarf_form_ref8] = 8,      [dwarf_form_sec_offset] = 4,
    [dwarf_form_ref_sup4] = 4,  [dwarf_form_strp_sup] = 4,  [dwarf_form_data16] = 16,
    [dwarf_form_line_strp] = 4, [dwarf_form_ref_sig8] = 8,  [dwarf_form_ref_sup8] = 8,
    [dwarf_form_strx1] = 1,     [dwarf_form_strx2] = 2,     [dwarf_form_strx3] = 3,
    [dwarf_form_strx4] = 4,     [dwarf_form_addrx1] = 1,    [dwarf_form_addrx2] = 2,
    [dwarf_form_addrx3] = 3,    [dwarf_form_addrx4] = 4,
};

static void section_find(const struct elf *e, const char *name, struct dwarf_section *out);
static int units_scan(struct dwarf *d);
static bool unit_header(struct dwarf_cursor *c, struct dwarf_unit *out);
static int arrays_reserve(struct dwarf *d);
static void aranges_read(struct dwarf *d);
static bool unit_by_offset(const struct dwarf *d, uint64_t info_offset, uint32_t *out);
static bool unit_by_address(const struct dwarf *d, uint64_t address_file, uint32_t *out);
static void range_append(struct dwarf *d, uint32_t unit, uint64_t low, uint64_t high);
static void ranges_swap(struct dwarf *d, uint32_t a, uint32_t b);
static void ranges_sift(struct dwarf *d, uint32_t root, uint32_t count);
static void ranges_sort(struct dwarf *d);
static void ranges_resolve(struct dwarf *d);
static bool unit_index(struct dwarf *d, uint32_t unit);
static bool abbrev_table_read(const struct dwarf *d, uint32_t offset,
                              struct dwarf_abbrev_table *out);
static const struct dwarf_abbrev *abbrev_find(const struct dwarf_abbrev_table *t, uint64_t code);
static bool die_read(const struct dwarf_unit *unit, const struct dwarf_abbrev_table *table,
                     struct dwarf_cursor *c, const struct dwarf_abbrev **abbrev_out,
                     struct dwarf_die_values *values_out);
static bool form_value(struct dwarf_cursor *c, const struct dwarf_unit *unit, uint64_t form,
                       int64_t implicit_const, uint64_t *number_out);
static bool form_block(struct dwarf_cursor *c, uint64_t length_bytes);
static enum dwarf_form_class form_class(uint64_t form);
static dwarf_strid name_strid(uint64_t form, uint64_t number);
static dwarf_strid strid_make(enum dwarf_string_section section, uint64_t offset);
static uint64_t high_pc_absolute(const struct dwarf_die_values *values);
static bool function_append(struct dwarf *d, uint32_t unit, const struct dwarf_die_values *values);
static bool function_search(const struct dwarf *d, uint32_t unit, uint64_t address_file,
                            struct dwarf_function_info *out);
static void function_info(const struct dwarf *d, uint32_t function,
                          struct dwarf_function_info *out);
static bool names_build(struct dwarf *d);
static void names_insert(struct dwarf *d, uint32_t function);
static bool names_probe(const struct dwarf *d, const char *name, uint32_t *out);
static uint32_t name_hash(const char *name);

int dwarf_open(struct dwarf *d, const struct elf *e, struct arena *arena) {
    assert(d != NULL);
    assert(e != NULL);
    assert(arena != NULL);

    *d = (struct dwarf){ .elf = e, .arena = arena };

    section_find(e, ".debug_info", &d->info);
    section_find(e, ".debug_abbrev", &d->abbrev);
    section_find(e, ".debug_str", &d->str);
    section_find(e, ".debug_line_str", &d->line_str);
    section_find(e, ".debug_aranges", &d->aranges);

    // A stripped binary is a fact about the target, not a failure of wraith.
    if (d->info.data == NULL) return 0;
    if (d->abbrev.data == NULL) return 0;

    if (arrays_reserve(d) == -1) return -1;
    if (units_scan(d) == -1) return -1;

    aranges_read(d);
    ranges_sort(d);

    assert(d->ranges_count <= d->ranges_capacity);
    assert(d->functions_count == 0);  // 7.2: not one DIE has been read.
    return 0;
}

bool dwarf_has_info(const struct dwarf *d) {
    assert(d != NULL);
    if (d->info.data == NULL) return false;
    return d->units_count > 0;
}

uint32_t dwarf_units_count(const struct dwarf *d) {
    assert(d != NULL);
    assert(d->units_count <= UINT32_MAX);
    return d->units_count;
}

uint32_t dwarf_units_indexed(const struct dwarf *d) {
    assert(d != NULL);
    uint32_t indexed = 0;
    for (uint32_t i = 0; i < d->units_count; i++) {
        if (d->units[i].state == dwarf_unit_state_indexed) indexed++;
    }
    assert(indexed <= d->units_count);
    return indexed;
}

bool dwarf_function_containing(struct dwarf *d, uint64_t address_file,
                               struct dwarf_function_info *out) {
    assert(d != NULL);
    assert(out != NULL);

    *out = (struct dwarf_function_info){0};
    if (d->units_count == 0) return false;

    uint32_t unit = 0;
    if (!unit_by_address(d, address_file, &unit)) {
        ranges_resolve(d);
        if (!unit_by_address(d, address_file, &unit)) return false;
    }

    if (!unit_index(d, unit)) return false;
    return function_search(d, unit, address_file, out);
}

bool dwarf_function_by_name(struct dwarf *d, const char *name,
                            struct dwarf_function_info *out) {
    assert(d != NULL);
    assert(name != NULL);
    assert(out != NULL);

    *out = (struct dwarf_function_info){0};
    if (!names_build(d)) return false;

    uint32_t function = 0;
    if (!names_probe(d, name, &function)) return false;

    assert(function < d->functions_count);
    function_info(d, function, out);
    return true;
}

const char *dwarf_string(const struct dwarf *d, dwarf_strid id) {
    assert(d != NULL);
    if (id == dwarf_strid_none) return NULL;

    const uint32_t section = id >> dwarf_strid_offset_bits;
    const uint64_t offset = id & dwarf_strid_offset_max;

    const struct dwarf_section *source = NULL;
    if (section == dwarf_string_section_str) source = &d->str;
    if (section == dwarf_string_section_line_str) source = &d->line_str;
    if (section == dwarf_string_section_info) source = &d->info;
    if (source == NULL) return NULL;
    if (source->data == NULL) return NULL;
    if (offset >= source->size_bytes) return NULL;

    struct dwarf_cursor c = { .data = source->data, .size_bytes = source->size_bytes,
                              .offset = offset };
    return dwarf_cursor_string(&c);
}

static void section_find(const struct elf *e, const char *name, struct dwarf_section *out) {
    assert(e != NULL);
    assert(name != NULL);
    assert(out != NULL);

    *out = (struct dwarf_section){0};
    (void)elf_section_bytes(e, name, &out->data, &out->size_bytes);
}

static int arrays_reserve(struct dwarf *d) {
    assert(d != NULL);
    assert(d->info.data != NULL);

    const uint64_t units_max = (d->info.size_bytes / dwarf_unit_bytes_min) + 1;
    const uint64_t functions_max = (d->info.size_bytes / dwarf_function_bytes_min) + 1;
    // Every arange tuple plus one fallback entry for every unit it misses.
    const uint64_t ranges_max = (d->aranges.size_bytes / dwarf_arange_bytes) + units_max;

    if (units_max > UINT32_MAX) return -1;
    if (functions_max > UINT32_MAX) return -1;
    if (ranges_max > UINT32_MAX) return -1;

    d->units = arena_alloc(d->arena, units_max * sizeof *d->units, 64);
    d->functions = arena_alloc(d->arena, functions_max * sizeof *d->functions, 64);
    d->range_low = arena_alloc(d->arena, ranges_max * sizeof *d->range_low, 64);
    d->range_high = arena_alloc(d->arena, ranges_max * sizeof *d->range_high, 64);
    d->range_unit = arena_alloc(d->arena, ranges_max * sizeof *d->range_unit, 64);

    if (d->units == NULL) return -1;
    if (d->functions == NULL) return -1;
    if (d->range_low == NULL) return -1;
    if (d->range_high == NULL) return -1;
    if (d->range_unit == NULL) return -1;

    d->functions_capacity = (uint32_t)functions_max;
    d->ranges_capacity = (uint32_t)ranges_max;
    return 0;
}

// Reads unit headers and nothing else. This function is where 7.2 lives.
static int units_scan(struct dwarf *d) {
    assert(d != NULL);
    assert(d->units != NULL);

    struct dwarf_cursor c = { .data = d->info.data, .size_bytes = d->info.size_bytes };
    const uint32_t units_max = (uint32_t)((d->info.size_bytes / dwarf_unit_bytes_min) + 1);

    for (uint32_t i = 0; i < units_max; i++) {
        if (c.offset + dwarf_unit_bytes_min > c.size_bytes) break;

        struct dwarf_unit unit = { .offset = (uint32_t)c.offset };
        const bool supported = unit_header(&c, &unit);
        if (unit.length_bytes == 0) break;
        if (!supported) unit.state = dwarf_unit_state_unsupported;

        assert(d->units_count < units_max);
        d->units[d->units_count] = unit;
        d->units_count++;

        c.offset = (uint64_t)unit.offset + unit.length_bytes;
        c.overrun = false;
    }

    assert(d->units_count <= units_max);
    return 0;
}

static bool unit_header(struct dwarf_cursor *c, struct dwarf_unit *out) {
    assert(c != NULL);
    assert(out != NULL);

    const uint64_t unit_length = dwarf_cursor_fixed(c, 4);
    if (unit_length == 0) return false;
    if (unit_length == 0xffffffff) return false;

    out->length_bytes = (uint32_t)(unit_length + 4);
    out->version = (uint16_t)dwarf_cursor_fixed(c, 2);
    if (out->version < 2) return false;
    if (out->version > 5) return false;

    if (out->version >= 5) {
        const uint8_t unit_type = (uint8_t)dwarf_cursor_fixed(c, 1);
        out->address_size = (uint8_t)dwarf_cursor_fixed(c, 1);
        out->abbrev_offset = (uint32_t)dwarf_cursor_fixed(c, 4);
        if (unit_type != dwarf_unit_type_compile) return false;
    } else {
        out->abbrev_offset = (uint32_t)dwarf_cursor_fixed(c, 4);
        out->address_size = (uint8_t)dwarf_cursor_fixed(c, 1);
    }

    out->die_offset = (uint32_t)c->offset;

    if (c->overrun) return false;
    if (out->address_size != 8) return false;
    return true;
}

static void aranges_read(struct dwarf *d) {
    assert(d != NULL);
    if (d->aranges.data == NULL) return;

    struct dwarf_cursor c = { .data = d->aranges.data, .size_bytes = d->aranges.size_bytes };
    const uint32_t sets_max = (uint32_t)((d->aranges.size_bytes / dwarf_arange_bytes) + 1);

    for (uint32_t set = 0; set < sets_max; set++) {
        if (c.offset + dwarf_arange_bytes > c.size_bytes) break;

        const uint64_t set_start = c.offset;
        const uint64_t set_length = dwarf_cursor_fixed(&c, 4);
        if (set_length == 0) break;
        if (set_length == 0xffffffff) break;

        const uint64_t set_end = set_start + 4 + set_length;
        const uint16_t version = (uint16_t)dwarf_cursor_fixed(&c, 2);
        const uint64_t info_offset = dwarf_cursor_fixed(&c, 4);
        const uint8_t address_size = (uint8_t)dwarf_cursor_fixed(&c, 1);
        const uint8_t segment_size = (uint8_t)dwarf_cursor_fixed(&c, 1);
        if (c.overrun) break;
        if (set_end > c.size_bytes) break;

        uint32_t unit = 0;
        bool usable = unit_by_offset(d, info_offset, &unit);
        if (version != 2) usable = false;
        if (address_size != 8) usable = false;
        if (segment_size != 0) usable = false;

        const uint64_t align = (2 * (uint64_t)address_size) - 1;
        c.offset = set_start + ((((c.offset - set_start) + align) & ~align));

        const uint32_t tuples_max = (uint32_t)((set_length / dwarf_arange_bytes) + 1);
        for (uint32_t i = 0; i < tuples_max; i++) {
            if (c.offset + dwarf_arange_bytes > set_end) break;
            const uint64_t low = dwarf_cursor_fixed(&c, 8);
            const uint64_t length = dwarf_cursor_fixed(&c, 8);
            if (length == 0) {
                if (low == 0) break;  // The terminating pair.
                continue;
            }
            if (usable) range_append(d, unit, low, low + length);
        }

        c.offset = set_end;
        c.overrun = false;
    }
}

// Units are stored in .debug_info order, so this is a binary search on offset.
static bool unit_by_offset(const struct dwarf *d, uint64_t info_offset, uint32_t *out) {
    assert(d != NULL);
    assert(out != NULL);

    uint32_t low = 0;
    uint32_t high = d->units_count;
    for (uint32_t step = 0; step < dwarf_binary_search_steps_max; step++) {
        if (low >= high) break;
        const uint32_t middle = low + ((high - low) / 2);
        if (d->units[middle].offset < info_offset) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }

    if (low >= d->units_count) return false;
    if (d->units[low].offset != info_offset) return false;
    *out = low;
    return true;
}

static void range_append(struct dwarf *d, uint32_t unit, uint64_t low, uint64_t high) {
    assert(d != NULL);
    assert(unit < d->units_count);
    if (high <= low) return;
    if (d->ranges_count == d->ranges_capacity) return;

    d->range_low[d->ranges_count] = low;
    d->range_high[d->ranges_count] = high;
    d->range_unit[d->ranges_count] = unit;
    d->ranges_count++;
    d->units[unit].has_range = true;

    assert(d->ranges_count <= d->ranges_capacity);
}

static void ranges_swap(struct dwarf *d, uint32_t a, uint32_t b) {
    dwarf_assert_hot(a < d->ranges_count);
    dwarf_assert_hot(b < d->ranges_count);

    const uint64_t low = d->range_low[a];
    const uint64_t high = d->range_high[a];
    const uint32_t unit = d->range_unit[a];
    d->range_low[a] = d->range_low[b];
    d->range_high[a] = d->range_high[b];
    d->range_unit[a] = d->range_unit[b];
    d->range_low[b] = low;
    d->range_high[b] = high;
    d->range_unit[b] = unit;
}

static void ranges_sift(struct dwarf *d, uint32_t root, uint32_t count) {
    dwarf_assert_hot(d != NULL);
    dwarf_assert_hot(count <= d->ranges_count);

    uint32_t parent = root;
    // The path to a leaf is shorter than the heap, so count bounds the descent.
    for (uint32_t step = 0; step < count; step++) {
        const uint32_t left = (2 * parent) + 1;
        if (left >= count) return;

        uint32_t largest = parent;
        if (d->range_low[left] > d->range_low[largest]) largest = left;
        const uint32_t right = left + 1;
        if (right < count) {
            if (d->range_low[right] > d->range_low[largest]) largest = right;
        }
        if (largest == parent) return;

        ranges_swap(d, parent, largest);
        parent = largest;
    }
}

static void ranges_sort(struct dwarf *d) {
    assert(d != NULL);
    const uint32_t count = d->ranges_count;
    // The left-child index is 2i+1, so half the index space is the safe ceiling.
    assert(count < (UINT32_MAX / 2));
    if (count < 2) return;

    for (uint32_t i = count / 2; i > 0; i--) ranges_sift(d, i - 1, count);
    for (uint32_t end = count; end > 1; end--) {
        ranges_swap(d, 0, end - 1);
        ranges_sift(d, 0, end - 1);
    }

    for (uint32_t i = 1; i < count; i++) assert(d->range_low[i - 1] <= d->range_low[i]);
}

static bool unit_by_address(const struct dwarf *d, uint64_t address_file, uint32_t *out) {
    assert(d != NULL);
    assert(out != NULL);
    if (d->ranges_count == 0) return false;

    uint32_t low = 0;
    uint32_t high = d->ranges_count;
    //500 leetcode for THIS, WHERE IS MY DUAL MAX/MIN HEAP MEDIAN SEARCH????
    //also no recursion
    for (uint32_t step = 0; step < dwarf_binary_search_steps_max; step++) {
        if (low >= high) break;
        const uint32_t middle = low + ((high - low) / 2);
        if (d->range_low[middle] <= address_file) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }

    if (low == 0) return false;
    const uint32_t found = low - 1;
    if (address_file >= d->range_high[found]) return false;

    *out = d->range_unit[found];
    assert(*out < d->units_count);
    return true;
}

static void ranges_resolve(struct dwarf *d) {
    assert(d != NULL);
    if (d->ranges_resolved) return;
    // Set before the work, so a unit that cannot be read is not retried forever.
    d->ranges_resolved = true;

    for (uint32_t i = 0; i < d->units_count; i++) {
        struct dwarf_unit *const unit = &d->units[i];
        if (unit->has_range) continue;
        if (unit->state == dwarf_unit_state_unsupported) continue;

        struct dwarf_abbrev_table table;
        if (!abbrev_table_read(d, unit->abbrev_offset, &table)) continue;

        struct dwarf_cursor c = { .data = d->info.data,
                                  .size_bytes = (uint64_t)unit->offset + unit->length_bytes,
                                  .offset = unit->die_offset };

        const struct dwarf_abbrev *abbrev = NULL;
        struct dwarf_die_values values;
        if (!die_read(unit, &table, &c, &abbrev, &values)) continue;
        if (abbrev == NULL) continue;
        if (abbrev->tag != dwarf_tag_compile_unit) continue;
        if (!values.has_low_pc) continue;
        if (!values.has_high_pc) continue;

        range_append(d, i, values.low_pc, high_pc_absolute(&values));
    }

    ranges_sort(d);
}

static bool unit_index(struct dwarf *d, uint32_t unit_id) {
    assert(d != NULL);
    assert(unit_id < d->units_count);

    struct dwarf_unit *const unit = &d->units[unit_id];
    if (unit->state == dwarf_unit_state_indexed) return true;
    if (unit->state == dwarf_unit_state_unsupported) return false;

    struct dwarf_abbrev_table table;
    if (!abbrev_table_read(d, unit->abbrev_offset, &table)) {
        unit->state = dwarf_unit_state_unsupported;
        return false;
    }

    const uint64_t unit_end = (uint64_t)unit->offset + unit->length_bytes;
    struct dwarf_cursor c = { .data = d->info.data, .size_bytes = unit_end,
                              .offset = unit->die_offset };
    unit->functions_first = d->functions_count;

    uint32_t depth = 0;
    const uint32_t dies_max = unit->length_bytes;  // Every DIE is at least a byte.
    bool complete = false;
    for (uint32_t die = 0; die < dies_max; die++) {
        const struct dwarf_abbrev *abbrev = NULL;
        struct dwarf_die_values values;
        if (!die_read(unit, &table, &c, &abbrev, &values)) break;

        if (abbrev == NULL) {
            if (depth == 0) break;  // A terminator with nothing open is a desync.
            depth--;
            if (depth == 0) { complete = true; break; }
            continue;
        }

        if (abbrev->tag == dwarf_tag_subprogram) {
            if (!function_append(d, unit_id, &values)) break;
        }

        if (abbrev->has_children) {
            depth++;
        } else {
            if (depth == 0) { complete = true; break; }  // A childless root is the unit.
        }
    }

    if (c.offset != unit_end) complete = false;
    if (!complete) {
        d->functions_count = unit->functions_first;
        unit->functions_count = 0;
        unit->state = dwarf_unit_state_unsupported;
        return false;
    }

    unit->state = dwarf_unit_state_indexed;
    return true;
}

static bool abbrev_table_read(const struct dwarf *d, uint32_t offset,
                              struct dwarf_abbrev_table *out) {
    assert(d != NULL);
    assert(out != NULL);
    if (d->abbrev.data == NULL) return false;
    if (offset >= d->abbrev.size_bytes) return false;

    struct dwarf_cursor c = { .data = d->abbrev.data, .size_bytes = d->abbrev.size_bytes,
                              .offset = offset };
    *out = (struct dwarf_abbrev_table){ .abbrevs = dwarf_abbrev_pool,
                                        .attributes = dwarf_abbrev_attribute_pool };
    uint32_t count = 0;
    uint32_t attributes = 0;

    for (uint32_t i = 0; i < dwarf_abbrevs_max; i++) {
        const uint64_t code = dwarf_cursor_uleb128(&c);
        if (c.overrun) return false;
        if (code == 0) break;  // The end of this table, not of the section.
        if (code > UINT32_MAX) return false;

        const uint64_t tag = dwarf_cursor_uleb128(&c);
        const uint8_t has_children = (uint8_t)dwarf_cursor_fixed(&c, 1);
        if (c.overrun) return false;
        if (tag > UINT16_MAX) return false;

        struct dwarf_abbrev abbrev = { .code = (uint32_t)code, .tag = (uint16_t)tag,
                                       .has_children = has_children != 0,
                                       .attributes_first = attributes };

        for (uint32_t a = 0; a < dwarf_abbrev_attributes_max; a++) {
            const uint64_t attribute = dwarf_cursor_uleb128(&c);
            const uint64_t form = dwarf_cursor_uleb128(&c);
            if (c.overrun) return false;
            if (attribute == 0) {
                if (form != 0) return false;
                break;
            }
            if (attribute > UINT16_MAX) return false;
            if (form > UINT16_MAX) return false;

            int64_t implicit_const = 0;
            if (form == dwarf_form_implicit_const) {
                implicit_const = dwarf_cursor_sleb128(&c);
                if (c.overrun) return false;
            }

            if (attributes == dwarf_abbrev_attributes_max) return false;
            dwarf_abbrev_attribute_pool[attributes] = (struct dwarf_abbrev_attribute){
                .implicit_const = implicit_const,
                .attribute = (uint16_t)attribute,
                .form = (uint16_t)form,
            };
            attributes++;
            abbrev.attributes_count++;
        }

        if (count == dwarf_abbrevs_max) return false;
        dwarf_abbrev_pool[count] = abbrev;
        count++;
    }

    out->count = count;
    assert(out->count <= dwarf_abbrevs_max);
    return true;
}

static const struct dwarf_abbrev *abbrev_find(const struct dwarf_abbrev_table *t, uint64_t code) {
    dwarf_assert_hot(t != NULL);
    dwarf_assert_hot(code > 0);

    if (code <= t->count) {
        if (t->abbrevs[code - 1].code == code) return &t->abbrevs[code - 1];
    }
    for (uint32_t i = 0; i < t->count; i++) {
        if (t->abbrevs[i].code == code) return &t->abbrevs[i];
    }
    return NULL;
}

static bool die_read(const struct dwarf_unit *unit, const struct dwarf_abbrev_table *table,
                     struct dwarf_cursor *c, const struct dwarf_abbrev **abbrev_out,
                     struct dwarf_die_values *values_out) {
    dwarf_assert_hot(abbrev_out != NULL);
    dwarf_assert_hot(values_out != NULL);

    *abbrev_out = NULL;
    *values_out = (struct dwarf_die_values){0};

    const uint64_t code = dwarf_cursor_uleb128(c);
    if (c->overrun) return false;
    if (code == 0) return true;

    const struct dwarf_abbrev *const abbrev = abbrev_find(table, code);
    if (abbrev == NULL) return false;  // No shape means no length means no next DIE.

    for (uint32_t i = 0; i < abbrev->attributes_count; i++) {
        const struct dwarf_abbrev_attribute *const spec =
            &table->attributes[abbrev->attributes_first + i];

        uint64_t number = 0;
        if (!form_value(c, unit, spec->form, spec->implicit_const, &number)) return false;

        switch (spec->attribute) {
        case dwarf_attribute_name:
            values_out->name = name_strid(spec->form, number);
            break;
        case dwarf_attribute_low_pc:
            values_out->low_pc = number;
            values_out->has_low_pc = true;
            break;
        case dwarf_attribute_high_pc:
            values_out->high_pc_raw = number;
            values_out->has_high_pc = true;
            values_out->high_pc_is_length = form_class(spec->form) == dwarf_form_class_constant;
            break;
        default:
            break;
        }
    }

    if (c->overrun) return false;
    *abbrev_out = abbrev;
    return true;
}

// Always consumes exactly the form's bytes; number_out is meaningful only for
// the classes this chapter reads. Returns false when the length is unknowable.
static bool form_value(struct dwarf_cursor *c, const struct dwarf_unit *unit, uint64_t form,
                       int64_t implicit_const, uint64_t *number_out) {
    dwarf_assert_hot(c != NULL);
    dwarf_assert_hot(number_out != NULL);

    *number_out = 0;

    for (uint32_t redirect = 0; redirect < 2; redirect++) {
        if (form != dwarf_form_indirect) break;
        form = dwarf_cursor_uleb128(c);
        if (c->overrun) return false;
    }
    if (form == dwarf_form_indirect) return false;

    if (form < (sizeof dwarf_form_width / sizeof dwarf_form_width[0])) {
        const uint8_t width = dwarf_form_width[form];
        if (width > 0) {
            *number_out = dwarf_cursor_fixed(c, width);
            return !c->overrun;
        }
    }

    switch (form) {
    case dwarf_form_addr:
        *number_out = dwarf_cursor_fixed(c, unit->address_size);
        return !c->overrun;
    case dwarf_form_string: {
        // The handle is the offset of the bytes inside .debug_info itself.
        const uint64_t start = c->offset;
        if (dwarf_cursor_string(c) == NULL) return false;
        *number_out = start;
        return true;
    }
    case dwarf_form_udata:
    case dwarf_form_ref_udata:
    case dwarf_form_strx:
    case dwarf_form_addrx:
    case dwarf_form_loclistx:
    case dwarf_form_rnglistx:
        *number_out = dwarf_cursor_uleb128(c);
        return !c->overrun;
    case dwarf_form_sdata:
        *number_out = (uint64_t)dwarf_cursor_sleb128(c);
        return !c->overrun;
    case dwarf_form_block1: {
        const uint64_t length_bytes = dwarf_cursor_fixed(c, 1);
        return form_block(c, length_bytes);
    }
    case dwarf_form_block2: {
        const uint64_t length_bytes = dwarf_cursor_fixed(c, 2);
        return form_block(c, length_bytes);
    }
    case dwarf_form_block4: {
        const uint64_t length_bytes = dwarf_cursor_fixed(c, 4);
        return form_block(c, length_bytes);
    }
    case dwarf_form_block:
    case dwarf_form_exprloc: {
        const uint64_t length_bytes = dwarf_cursor_uleb128(c);
        return form_block(c, length_bytes);
    }
    case dwarf_form_flag_present:
        *number_out = 1;
        return true;
    case dwarf_form_implicit_const:
        *number_out = (uint64_t)implicit_const;
        return true;
    default:
        // An unknown form has an unknown length, so nothing after it can be
        // found. Report it; never guess a width.
        return false;
    }
}

static bool form_block(struct dwarf_cursor *c, uint64_t length_bytes) {
    dwarf_assert_hot(c != NULL);
    if (c->overrun) return false;
    return dwarf_cursor_bytes(c, length_bytes) != NULL;
}

static enum dwarf_form_class form_class(uint64_t form) {
    switch (form) {
    case dwarf_form_addr:
    case dwarf_form_addrx:
    case dwarf_form_addrx1:
    case dwarf_form_addrx2:
    case dwarf_form_addrx3:
    case dwarf_form_addrx4:
        return dwarf_form_class_address;
    case dwarf_form_data1:
    case dwarf_form_data2:
    case dwarf_form_data4:
    case dwarf_form_data8:
    case dwarf_form_data16:
    case dwarf_form_sdata:
    case dwarf_form_udata:
    case dwarf_form_implicit_const:
        return dwarf_form_class_constant;
    case dwarf_form_string:
    case dwarf_form_strp:
    case dwarf_form_strp_sup:
    case dwarf_form_line_strp:
    case dwarf_form_strx:
    case dwarf_form_strx1:
    case dwarf_form_strx2:
    case dwarf_form_strx3:
    case dwarf_form_strx4:
        return dwarf_form_class_string;
    default:
        return dwarf_form_class_unknown;
    }
}

static dwarf_strid name_strid(uint64_t form, uint64_t number) {
    switch (form) {
    case dwarf_form_strp:
    case dwarf_form_strp_sup:
        return strid_make(dwarf_string_section_str, number);
    case dwarf_form_line_strp:
        // GCC puts file names here. Resolving this offset against .debug_str
        // instead yields a real, correctly terminated, completely wrong string.
        return strid_make(dwarf_string_section_line_str, number);
    case dwarf_form_string:
        return strid_make(dwarf_string_section_info, number);
    default:
        return dwarf_strid_none;
    }
}

static dwarf_strid strid_make(enum dwarf_string_section section, uint64_t offset) {
    dwarf_assert_hot(section != dwarf_string_section_none);
    if (offset > dwarf_strid_offset_max) return dwarf_strid_none;
    return ((dwarf_strid)section << dwarf_strid_offset_bits) | (dwarf_strid)offset;
}

static uint64_t high_pc_absolute(const struct dwarf_die_values *values) {
    dwarf_assert_hot(values != NULL);
    dwarf_assert_hot(values->has_high_pc);
    if (values->high_pc_is_length) return values->low_pc + values->high_pc_raw;
    return values->high_pc_raw;
}

static bool function_append(struct dwarf *d, uint32_t unit, const struct dwarf_die_values *values) {
    assert(d != NULL);
    assert(values != NULL);
    assert(unit < d->units_count);

    if (!values->has_low_pc) return true;
    if (!values->has_high_pc) return true;

    const uint64_t high_pc = high_pc_absolute(values);
    if (high_pc <= values->low_pc) return true;
    if (d->functions_count == d->functions_capacity) return false;

    d->functions[d->functions_count] = (struct dwarf_function){
        .low_pc = values->low_pc,
        .high_pc = high_pc,
        .name = values->name,
        .unit = unit,
    };
    d->functions_count++;
    d->units[unit].functions_count++;

    assert(d->functions_count <= d->functions_capacity);
    return true;
}

static bool function_search(const struct dwarf *d, uint32_t unit, uint64_t address_file,
                            struct dwarf_function_info *out) {
    assert(d != NULL);
    assert(unit < d->units_count);
    assert(out != NULL);

    const struct dwarf_unit *const entry = &d->units[unit];
    for (uint32_t i = 0; i < entry->functions_count; i++) {
        const uint32_t index = entry->functions_first + i;
        assert(index < d->functions_count);
        if (address_file < d->functions[index].low_pc) continue;
        if (address_file >= d->functions[index].high_pc) continue;
        function_info(d, index, out);
        return true;
    }
    return false;
}

static void function_info(const struct dwarf *d, uint32_t function,
                          struct dwarf_function_info *out) {
    assert(d != NULL);
    assert(function < d->functions_count);
    assert(out != NULL);

    const struct dwarf_function *const entry = &d->functions[function];
    *out = (struct dwarf_function_info){
        .name = dwarf_string(d, entry->name),
        .low_pc = entry->low_pc,
        .high_pc = entry->high_pc,
    };
}

static bool names_build(struct dwarf *d) {
    assert(d != NULL);
    if (d->names_built) return d->names != NULL;
    d->names_built = true;

    for (uint32_t i = 0; i < d->units_count; i++) (void)unit_index(d, i);
    if (d->functions_count == 0) return false;
    assert(d->functions_count < (UINT32_MAX / 2));

    uint32_t capacity = 16;
    // A load factor under one half is where open addressing keeps probes short.
    for (uint32_t i = 0; i < 32; i++) {
        if (capacity >= d->functions_count * 2) break;
        capacity *= 2;
    }

    d->names = arena_alloc(d->arena, (uint64_t)capacity * sizeof *d->names, 64);
    if (d->names == NULL) return false;
    memset(d->names, 0, (size_t)capacity * sizeof *d->names);
    d->names_capacity = capacity;

    for (uint32_t i = 0; i < d->functions_count; i++) names_insert(d, i);
    return true;
}

static void names_insert(struct dwarf *d, uint32_t function) {
    assert(d != NULL);
    assert(d->names != NULL);
    assert(function < d->functions_count);

    const char *const name = dwarf_string(d, d->functions[function].name);
    if (name == NULL) return;

    const uint32_t hash = name_hash(name);
    const uint32_t mask = d->names_capacity - 1;
    uint32_t slot = hash & mask;
    for (uint32_t step = 0; step < d->names_capacity; step++) {
        if (d->names[slot].hash == 0) {
            d->names[slot] = (struct dwarf_name_slot){ .hash = hash, .function = function };
            return;
        }
        slot = (slot + 1) & mask;
    }
}

static bool names_probe(const struct dwarf *d, const char *name, uint32_t *out) {
    assert(d != NULL);
    assert(name != NULL);
    assert(out != NULL);
    if (d->names == NULL) return false;

    const uint32_t hash = name_hash(name);
    const uint32_t mask = d->names_capacity - 1;
    uint32_t slot = hash & mask;
    for (uint32_t step = 0; step < d->names_capacity; step++) {
        const struct dwarf_name_slot entry = d->names[slot];
        if (entry.hash == 0) return false;  // An empty slot ends the probe run.
        if (entry.hash == hash) {
            const char *const candidate = dwarf_string(d, d->functions[entry.function].name);
            if (candidate != NULL) {
                // The hash is stored beside the entry, so a mismatch costs one
                // integer compare and strcmp runs at most once per lookup.
                if (strcmp(candidate, name) == 0) {
                    *out = entry.function;
                    return true;
                }
            }
        }
        slot = (slot + 1) & mask;
    }
    return false;
}

static uint32_t name_hash(const char *name) {
    dwarf_assert_hot(name != NULL);

    uint32_t hash = 2166136261u;  // FNV-1a, 32-bit.
    for (uint32_t i = 0; i < dwarf_name_bytes_max; i++) {
        if (name[i] == '\0') break;
        hash ^= (uint32_t)(uint8_t)name[i];
        hash *= 16777619u;
    }
    // Zero marks an empty slot, so no real hash is allowed to be zero.
    if (hash == 0) return 1;
    return hash;
}
