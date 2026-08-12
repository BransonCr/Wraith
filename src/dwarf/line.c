// The .debug_line number program, decoded per unit into a sorted address-to-line table.
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "arena/arena.h"
#include "dwarf/dwarf.h"
#include "dwarf/dwarf_internal.h"

enum {
    // opcode_base is a byte, but no producer defines past the twelve standard ones.
    dwarf_line_standard_opcodes_max = 32,
    dwarf_line_entry_formats_max = 8,
    dwarf_line_directories_max = 1024,
    dwarf_line_files_max = 8192,
    dwarf_line_search_steps_max = 32,
};

enum dwarf_line_opcode {
    dwarf_line_opcode_extended = 0x00,
    dwarf_line_opcode_copy = 0x01,
    dwarf_line_opcode_advance_pc = 0x02,
    dwarf_line_opcode_advance_line = 0x03,
    dwarf_line_opcode_set_file = 0x04,
    dwarf_line_opcode_negate_statement = 0x06,
    dwarf_line_opcode_const_add_pc = 0x08,
    dwarf_line_opcode_fixed_advance_pc = 0x09,
    dwarf_line_opcode_set_prologue_end = 0x0a,
};

enum dwarf_line_extended {
    dwarf_line_extended_end_sequence = 0x01,
    dwarf_line_extended_set_address = 0x02,
};

enum dwarf_line_content {
    dwarf_line_content_path = 0x01,
    dwarf_line_content_directory_index = 0x02,
};

struct dwarf_line_header {
    uint64_t program_offset;
    uint64_t end_offset;
    uint64_t files_offset;
    dwarf_strid comp_dir;
    uint32_t directories_count;
    int32_t line_base;
    uint16_t version;
    uint8_t line_range;
    uint8_t opcode_base;
    uint8_t instruction_bytes_min;
    uint8_t file_base;
    bool default_is_statement;
    uint8_t standard_lengths[dwarf_line_standard_opcodes_max];
};

struct dwarf_line_format {
    uint32_t content;
    uint32_t form;
};

struct dwarf_line_entry {
    dwarf_strid path;
    uint32_t directory;
};

struct dwarf_line_registers {
    uint64_t address;
    int64_t line;
    uint32_t file;
    uint16_t flags;
};

static dwarf_strid dwarf_line_directory_pool[dwarf_line_directories_max];

static bool tables_reserve(struct dwarf *d);
static const struct dwarf_line_table *table_read(struct dwarf *d, uint32_t unit_id);
static bool header_read(const struct dwarf *d, uint64_t offset,
                        struct dwarf_line_header *out);
static bool directories_read(struct dwarf_cursor *c, struct dwarf_line_header *h);
static uint32_t formats_read(struct dwarf_cursor *c, struct dwarf_line_format *out);
static bool entry_read(struct dwarf_cursor *c, const struct dwarf_line_format *formats,
                       uint32_t formats_count, struct dwarf_line_entry *out);
static uint32_t files_read(const struct dwarf *d, const struct dwarf_line_header *h,
                           struct dwarf_line_file *files, uint32_t capacity);
static struct dwarf_line_file file_make(const struct dwarf_line_header *h,
                                        const struct dwarf_line_entry *entry);
static dwarf_strid directory_strid(const struct dwarf_line_header *h, uint32_t index);
static uint32_t program_run(const struct dwarf *d, const struct dwarf_line_header *h,
                            struct dwarf_line_row *rows, uint32_t capacity);
static bool opcode_standard(const struct dwarf_line_header *h, struct dwarf_cursor *c,
                            struct dwarf_line_registers *r, uint8_t opcode);
static bool opcode_extended(struct dwarf_cursor *c, struct dwarf_line_registers *r);
static void opcode_skip(const struct dwarf_line_header *h, struct dwarf_cursor *c,
                        uint8_t opcode);
static void registers_reset(struct dwarf_line_registers *r,
                            const struct dwarf_line_header *h);
static void registers_step(struct dwarf_line_registers *r,
                           const struct dwarf_line_header *h);
static void row_emit(struct dwarf_line_row *row, const struct dwarf_line_registers *r,
                     const struct dwarf_line_header *h);
static bool row_before(const struct dwarf_line_row *a, const struct dwarf_line_row *b);
static void rows_sift(struct dwarf_line_row *rows, uint32_t root, uint32_t count);
static void rows_sort(struct dwarf_line_row *rows, uint32_t count);
static bool row_at_or_below(const struct dwarf_line_table *t, uint64_t address,
                            uint32_t *out);
static bool row_matches(const struct dwarf *d, const struct dwarf_line_table *t,
                        const struct dwarf_line_row *row, const char *path, uint32_t line);
static bool path_matches(const char *directory, const char *file, const char *query);
static void line_info(const struct dwarf *d, const struct dwarf_line_table *t, uint32_t row,
                      struct dwarf_line_info *out);

bool dwarf_line_at_address(struct dwarf *d, uint64_t address_file,
                           struct dwarf_line_info *out) {
    assert(d != NULL);
    assert(out != NULL);

    *out = (struct dwarf_line_info){0};

    uint32_t unit_id = 0;
    if (!dwarf_unit_for_address(d, address_file, &unit_id)) return false;

    const struct dwarf_line_table *const table = table_read(d, unit_id);
    if (table == NULL) return false;

    uint32_t row = 0;
    if (!row_at_or_below(table, address_file, &row)) return false;
    // The terminator sits one past the last byte of a sequence, so it names no line.
    if ((table->rows[row].flags & dwarf_line_flag_end_sequence) != 0) return false;

    line_info(d, table, row, out);
    return true;
}

// A source line compiles to several addresses whenever it is a loop header.
uint32_t dwarf_line_addresses(struct dwarf *d, const char *path, uint32_t line,
                              uint64_t *out, uint32_t count_max) {
    assert(d != NULL);
    assert(path != NULL);
    assert(out != NULL);
    assert(count_max > 0);

    uint32_t count = 0;
    for (uint32_t unit_id = 0; unit_id < d->units_count; unit_id++) {
        const struct dwarf_line_table *const table = table_read(d, unit_id);
        if (table == NULL) continue;

        for (uint32_t row = 0; row < table->rows_count; row++) {
            if (count == count_max) return count;
            if (!row_matches(d, table, &table->rows[row], path, line)) continue;
            out[count] = table->rows[row].address;
            count++;
        }
    }

    assert(count <= count_max);
    return count;
}

uint32_t dwarf_lines_decoded(const struct dwarf *d) {
    assert(d != NULL);
    if (d->lines == NULL) return 0;

    uint32_t decoded = 0;
    for (uint32_t i = 0; i < d->units_count; i++) {
        if (d->lines[i].state == dwarf_line_state_ready) decoded++;
    }
    assert(decoded <= d->units_count);
    return decoded;
}

static bool tables_reserve(struct dwarf *d) {
    assert(d != NULL);
    if (d->lines != NULL) return true;
    if (d->units_count == 0) return false;

    const uint64_t size_bytes = (uint64_t)d->units_count * sizeof *d->lines;
    d->lines = arena_alloc(d->arena, size_bytes, 64);
    if (d->lines == NULL) return false;

    memset(d->lines, 0, (size_t)size_bytes);
    return true;
}

// Decodes one unit's program on first need and caches the rows. PERFORMANCE.md 7.3.
static const struct dwarf_line_table *table_read(struct dwarf *d, uint32_t unit_id) {
    assert(d != NULL);
    assert(unit_id < d->units_count);
    if (!tables_reserve(d)) return NULL;

    struct dwarf_line_table *const table = &d->lines[unit_id];
    if (table->state == dwarf_line_state_ready) return table;
    if (table->state == dwarf_line_state_unsupported) return NULL;
    // Set before the work, so a unit that cannot be read is not retried forever.
    table->state = dwarf_line_state_unsupported;

    if (d->line.data == NULL) return NULL;

    struct dwarf_unit_root root;
    if (!dwarf_unit_root(d, unit_id, &root)) return NULL;
    if (!root.has_stmt_list) return NULL;
    if (root.stmt_list >= d->line.size_bytes) return NULL;

    struct dwarf_line_header header = { .comp_dir = root.comp_dir };
    if (!header_read(d, root.stmt_list, &header)) return NULL;

    // Two passes: the program cannot say how many rows it emits without running it.
    const uint32_t files_count = files_read(d, &header, NULL, 0);
    const uint32_t rows_count = program_run(d, &header, NULL, 0);
    if (rows_count == 0) return NULL;

    if (files_count > 0) {
        const uint64_t bytes = (uint64_t)files_count * sizeof *table->files;
        table->files = arena_alloc(d->arena, bytes, 64);
        if (table->files == NULL) return NULL;
        table->files_count = files_read(d, &header, table->files, files_count);
    }

    table->rows = arena_alloc(d->arena, (uint64_t)rows_count * sizeof *table->rows, 64);
    if (table->rows == NULL) return NULL;
    table->rows_count = program_run(d, &header, table->rows, rows_count);
    assert(table->rows_count == rows_count);

    rows_sort(table->rows, table->rows_count);
    table->state = dwarf_line_state_ready;
    return table;
}

static bool header_read(const struct dwarf *d, uint64_t offset,
                        struct dwarf_line_header *out) {
    assert(d != NULL);
    assert(d->line.data != NULL);
    assert(out != NULL);

    struct dwarf_cursor c = { .data = d->line.data, .size_bytes = d->line.size_bytes,
                              .offset = offset };

    const uint64_t length = dwarf_cursor_fixed(&c, 4);
    if (length == 0) return false;
    if (length == 0xffffffff) return false;

    const uint64_t end = c.offset + length;
    if (end > d->line.size_bytes) return false;

    out->version = (uint16_t)dwarf_cursor_fixed(&c, 2);
    if (out->version < 2) return false;
    if (out->version > 5) return false;

    // DWARF 5 alone puts these two bytes here, and reading at the DWARF 4 offset
    // takes header_length from the wrong place and starts the program mid-header.
    if (out->version >= 5) {
        (void)dwarf_cursor_fixed(&c, 1);
        if (dwarf_cursor_fixed(&c, 1) != 0) return false;
    }

    const uint64_t header_length = dwarf_cursor_fixed(&c, 4);
    const uint64_t program = c.offset + header_length;

    out->instruction_bytes_min = (uint8_t)dwarf_cursor_fixed(&c, 1);
    // Anything but one is a VLIW target, where the address advance is a different sum.
    if (out->version >= 4) {
        if (dwarf_cursor_fixed(&c, 1) != 1) return false;
    }
    out->default_is_statement = dwarf_cursor_fixed(&c, 1) != 0;
    out->line_base = (int32_t)(int8_t)dwarf_cursor_fixed(&c, 1);
    out->line_range = (uint8_t)dwarf_cursor_fixed(&c, 1);
    out->opcode_base = (uint8_t)dwarf_cursor_fixed(&c, 1);

    if (c.overrun) return false;
    if (out->instruction_bytes_min == 0) return false;
    if (out->line_range == 0) return false;  // The special-opcode divisor.
    if (out->opcode_base == 0) return false;
    if (out->opcode_base > dwarf_line_standard_opcodes_max) return false;
    if (program > end) return false;

    for (uint8_t i = 0; i + 1 < out->opcode_base; i++) {
        out->standard_lengths[i] = (uint8_t)dwarf_cursor_fixed(&c, 1);
    }
    if (c.overrun) return false;

    out->program_offset = program;
    out->end_offset = end;
    out->file_base = out->version >= 5 ? 0 : 1;
    return directories_read(&c, out);
}

static bool directories_read(struct dwarf_cursor *c, struct dwarf_line_header *h) {
    dwarf_assert_hot(c != NULL);
    dwarf_assert_hot(h != NULL);

    h->directories_count = 0;

    if (h->version >= 5) {
        struct dwarf_line_format formats[dwarf_line_entry_formats_max];
        const uint32_t formats_count = formats_read(c, formats);
        if (formats_count == 0) return false;

        const uint64_t count = dwarf_cursor_uleb128(c);
        if (count > dwarf_line_directories_max) return false;
        for (uint64_t i = 0; i < count; i++) {
            struct dwarf_line_entry entry;
            if (!entry_read(c, formats, formats_count, &entry)) return false;
            dwarf_line_directory_pool[i] = entry.path;
        }
        h->directories_count = (uint32_t)count;
    } else {
        for (uint32_t i = 0; i < dwarf_line_directories_max; i++) {
            const uint64_t start = c->offset;
            const char *const name = dwarf_cursor_string(c);
            if (name == NULL) return false;
            if (name[0] == '\0') break;  // The empty string ends the list.
            dwarf_line_directory_pool[i] =
                dwarf_strid_make(dwarf_string_section_line, start);
            h->directories_count = i + 1;
        }
    }

    h->files_offset = c->offset;
    return !c->overrun;
}

// A DWARF 5 entry describes its own shape, so one loop reads any producer's layout.
static uint32_t formats_read(struct dwarf_cursor *c, struct dwarf_line_format *out) {
    dwarf_assert_hot(c != NULL);
    dwarf_assert_hot(out != NULL);

    const uint8_t count = (uint8_t)dwarf_cursor_fixed(c, 1);
    if (count == 0) return 0;
    if (count > dwarf_line_entry_formats_max) return 0;

    for (uint8_t i = 0; i < count; i++) {
        out[i].content = (uint32_t)dwarf_cursor_uleb128(c);
        out[i].form = (uint32_t)dwarf_cursor_uleb128(c);
    }
    if (c->overrun) return 0;
    return count;
}

static bool entry_read(struct dwarf_cursor *c, const struct dwarf_line_format *formats,
                       uint32_t formats_count, struct dwarf_line_entry *out) {
    dwarf_assert_hot(formats != NULL);
    dwarf_assert_hot(out != NULL);

    *out = (struct dwarf_line_entry){0};
    for (uint32_t i = 0; i < formats_count; i++) {
        uint64_t number = 0;
        if (!dwarf_form_value(c, 8, formats[i].form, 0, &number)) return false;

        if (formats[i].content == dwarf_line_content_path) {
            out->path = dwarf_form_strid(formats[i].form, number,
                                         dwarf_string_section_line);
        }
        if (formats[i].content == dwarf_line_content_directory_index) {
            out->directory = (uint32_t)number;
        }
    }
    return !c->overrun;
}

// Counts when files is NULL, fills otherwise; a DWARF 2 list carries no count.
static uint32_t files_read(const struct dwarf *d, const struct dwarf_line_header *h,
                           struct dwarf_line_file *files, uint32_t capacity) {
    dwarf_assert_hot(d != NULL);
    dwarf_assert_hot(h != NULL);

    // The header bounds the cursor, so a truncated table cannot reach the program.
    struct dwarf_cursor c = { .data = d->line.data, .size_bytes = h->program_offset,
                              .offset = h->files_offset };
    uint32_t count = 0;

    if (h->version >= 5) {
        struct dwarf_line_format formats[dwarf_line_entry_formats_max];
        const uint32_t formats_count = formats_read(&c, formats);
        if (formats_count == 0) return 0;

        const uint64_t total = dwarf_cursor_uleb128(&c);
        if (total > dwarf_line_files_max) return 0;

        for (uint64_t i = 0; i < total; i++) {
            struct dwarf_line_entry entry;
            if (!entry_read(&c, formats, formats_count, &entry)) break;
            if (files != NULL) {
                if (count == capacity) break;
                files[count] = file_make(h, &entry);
            }
            count++;
        }
        return count;
    }

    for (uint32_t i = 0; i < dwarf_line_files_max; i++) {
        const uint64_t start = c.offset;
        const char *const name = dwarf_cursor_string(&c);
        if (name == NULL) break;
        if (name[0] == '\0') break;

        struct dwarf_line_entry entry = {
            .path = dwarf_strid_make(dwarf_string_section_line, start),
            .directory = (uint32_t)dwarf_cursor_uleb128(&c),
        };
        (void)dwarf_cursor_uleb128(&c);  // Modification time.
        (void)dwarf_cursor_uleb128(&c);  // Length in bytes.
        if (c.overrun) break;

        if (files != NULL) {
            if (count == capacity) break;
            files[count] = file_make(h, &entry);
        }
        count++;
    }
    return count;
}

static struct dwarf_line_file file_make(const struct dwarf_line_header *h,
                                        const struct dwarf_line_entry *entry) {
    dwarf_assert_hot(h != NULL);
    dwarf_assert_hot(entry != NULL);

    return (struct dwarf_line_file){
        .directory = directory_strid(h, entry->directory),
        .name = entry->path,
    };
}

// DWARF 5 numbers directories from zero; before it, zero meant the compilation directory.
static dwarf_strid directory_strid(const struct dwarf_line_header *h, uint32_t index) {
    dwarf_assert_hot(h != NULL);
    dwarf_assert_hot(h->directories_count <= dwarf_line_directories_max);

    if (h->version >= 5) {
        if (index < h->directories_count) return dwarf_line_directory_pool[index];
        return dwarf_strid_none;
    }
    if (index == 0) return h->comp_dir;
    if (index - 1 < h->directories_count) return dwarf_line_directory_pool[index - 1];
    return dwarf_strid_none;
}

// Counts when rows is NULL, fills otherwise. Special opcodes are the hot majority.
static uint32_t program_run(const struct dwarf *d, const struct dwarf_line_header *h,
                            struct dwarf_line_row *rows, uint32_t capacity) {
    dwarf_assert_hot(d != NULL);
    dwarf_assert_hot(h != NULL);
    dwarf_assert_hot(h->line_range > 0);

    struct dwarf_cursor c = { .data = d->line.data, .size_bytes = h->end_offset,
                              .offset = h->program_offset };
    struct dwarf_line_registers registers;
    registers_reset(&registers, h);

    uint32_t count = 0;
    // Every instruction is at least one byte, so the program length bounds the loop.
    const uint64_t instructions_max = h->end_offset - h->program_offset;
    for (uint64_t i = 0; i < instructions_max; i++) {
        if (c.offset >= h->end_offset) break;

        const uint8_t opcode = (uint8_t)dwarf_cursor_fixed(&c, 1);
        bool emitted = false;
        if (opcode >= h->opcode_base) {
            const uint32_t adjusted = opcode - h->opcode_base;
            registers.address +=
                (uint64_t)(adjusted / h->line_range) * h->instruction_bytes_min;
            registers.line += h->line_base + (int32_t)(adjusted % h->line_range);
            emitted = true;
        } else {
            if (opcode == dwarf_line_opcode_extended) {
                emitted = opcode_extended(&c, &registers);
            } else {
                emitted = opcode_standard(h, &c, &registers, opcode);
            }
        }
        if (c.overrun) break;
        if (!emitted) continue;

        if (rows != NULL) {
            if (count == capacity) break;
            row_emit(&rows[count], &registers, h);
        }
        count++;
        registers_step(&registers, h);
    }
    return count;
}

// Only the opcodes whose state survives into a row; the rest skip by declared length.
static bool opcode_standard(const struct dwarf_line_header *h, struct dwarf_cursor *c,
                            struct dwarf_line_registers *r, uint8_t opcode) {
    dwarf_assert_hot(opcode > 0);
    dwarf_assert_hot(opcode < h->opcode_base);

    switch (opcode) {
    case dwarf_line_opcode_copy:
        return true;
    case dwarf_line_opcode_advance_pc:
        r->address += dwarf_cursor_uleb128(c) * h->instruction_bytes_min;
        return false;
    case dwarf_line_opcode_advance_line:
        r->line += dwarf_cursor_sleb128(c);
        return false;
    case dwarf_line_opcode_set_file:
        r->file = (uint32_t)dwarf_cursor_uleb128(c);
        return false;
    case dwarf_line_opcode_negate_statement:
        r->flags ^= dwarf_line_flag_statement;
        return false;
    case dwarf_line_opcode_const_add_pc:
        r->address += (uint64_t)((255 - h->opcode_base) / h->line_range) *
                      h->instruction_bytes_min;
        return false;
    case dwarf_line_opcode_fixed_advance_pc:
        r->address += dwarf_cursor_fixed(c, 2);  // Never scaled, by definition.
        return false;
    case dwarf_line_opcode_set_prologue_end:
        r->flags |= dwarf_line_flag_prologue_end;
        return false;
    default:
        break;
    }

    opcode_skip(h, c, opcode);
    return false;
}

static bool opcode_extended(struct dwarf_cursor *c, struct dwarf_line_registers *r) {
    dwarf_assert_hot(c != NULL);
    dwarf_assert_hot(r != NULL);

    const uint64_t length_bytes = dwarf_cursor_uleb128(c);
    if (c->overrun) return false;
    if (length_bytes == 0) {
        c->overrun = true;
        return false;
    }

    // The length is what makes an unknown extended opcode survivable.
    const uint64_t next = c->offset + length_bytes;
    const uint8_t opcode = (uint8_t)dwarf_cursor_fixed(c, 1);

    bool emitted = false;
    switch (opcode) {
    case dwarf_line_extended_end_sequence:
        r->flags |= dwarf_line_flag_end_sequence;
        emitted = true;
        break;
    case dwarf_line_extended_set_address: {
        const uint64_t width = length_bytes - 1;
        if (width < 1) break;
        if (width > 8) break;
        r->address = dwarf_cursor_fixed(c, (uint32_t)width);
        break;
    }
    default:
        break;
    }

    if (next > c->size_bytes) {
        c->overrun = true;
        return false;
    }
    c->offset = next;
    return emitted;
}

// The header's length table is the only thing that says where a vendor opcode ends.
static void opcode_skip(const struct dwarf_line_header *h, struct dwarf_cursor *c,
                        uint8_t opcode) {
    dwarf_assert_hot(opcode > 0);
    dwarf_assert_hot(opcode < h->opcode_base);

    const uint8_t operands = h->standard_lengths[opcode - 1];
    for (uint8_t i = 0; i < operands; i++) (void)dwarf_cursor_uleb128(c);
}

// The file register starts at one in every DWARF version, including 5.
static void registers_reset(struct dwarf_line_registers *r,
                            const struct dwarf_line_header *h) {
    dwarf_assert_hot(r != NULL);
    dwarf_assert_hot(h != NULL);

    *r = (struct dwarf_line_registers){ .line = 1, .file = 1 };
    if (h->default_is_statement) r->flags = dwarf_line_flag_statement;
}

static void registers_step(struct dwarf_line_registers *r,
                           const struct dwarf_line_header *h) {
    dwarf_assert_hot(r != NULL);
    dwarf_assert_hot(h != NULL);

    if ((r->flags & dwarf_line_flag_end_sequence) != 0) {
        registers_reset(r, h);
        return;
    }
    r->flags &= (uint16_t)~dwarf_line_flag_prologue_end;
}

static void row_emit(struct dwarf_line_row *row, const struct dwarf_line_registers *r,
                     const struct dwarf_line_header *h) {
    dwarf_assert_hot(row != NULL);
    dwarf_assert_hot(r != NULL);

    // The register is one-based before DWARF 5 and zero-based from it.
    uint32_t file = 0;
    if (r->file >= h->file_base) file = r->file - h->file_base;
    if (file > UINT16_MAX) file = 0;

    *row = (struct dwarf_line_row){
        .address = r->address,
        .line = r->line < 0 ? 0 : (uint32_t)r->line,
        .file = (uint16_t)file,
        .flags = r->flags,
    };
}

// A terminator sorts ahead of a live row at the same address, so the live row wins.
static bool row_before(const struct dwarf_line_row *a, const struct dwarf_line_row *b) {
    dwarf_assert_hot(a != NULL);
    dwarf_assert_hot(b != NULL);

    if (a->address != b->address) return a->address < b->address;
    return (a->flags & dwarf_line_flag_end_sequence) >
           (b->flags & dwarf_line_flag_end_sequence);
}

static void rows_sift(struct dwarf_line_row *rows, uint32_t root, uint32_t count) {
    dwarf_assert_hot(rows != NULL);
    dwarf_assert_hot(root < count);

    uint32_t parent = root;
    // The path to a leaf is shorter than the heap, so count bounds the descent.
    for (uint32_t step = 0; step < count; step++) {
        const uint32_t left = (2 * parent) + 1;
        if (left >= count) return;

        uint32_t largest = parent;
        if (row_before(&rows[largest], &rows[left])) largest = left;
        const uint32_t right = left + 1;
        if (right < count) {
            if (row_before(&rows[largest], &rows[right])) largest = right;
        }
        if (largest == parent) return;

        const struct dwarf_line_row swap = rows[parent];
        rows[parent] = rows[largest];
        rows[largest] = swap;
        parent = largest;
    }
}

// Sequences concatenate in program order, which linker garbage collection reorders.
static void rows_sort(struct dwarf_line_row *rows, uint32_t count) {
    assert(rows != NULL);
    // The left-child index is 2i+1, so half the index space is the safe ceiling.
    assert(count < (UINT32_MAX / 2));
    if (count < 2) return;

    for (uint32_t i = count / 2; i > 0; i--) rows_sift(rows, i - 1, count);
    for (uint32_t end = count; end > 1; end--) {
        const struct dwarf_line_row swap = rows[0];
        rows[0] = rows[end - 1];
        rows[end - 1] = swap;
        rows_sift(rows, 0, end - 1);
    }

    for (uint32_t i = 1; i < count; i++) assert(!row_before(&rows[i], &rows[i - 1]));
}

// A row means "this line holds from here", so a lookup wants the row at or below.
static bool row_at_or_below(const struct dwarf_line_table *t, uint64_t address,
                            uint32_t *out) {
    dwarf_assert_hot(t != NULL);
    dwarf_assert_hot(out != NULL);

    uint32_t low = 0;
    uint32_t high = t->rows_count;
    for (uint32_t step = 0; step < dwarf_line_search_steps_max; step++) {
        if (low >= high) break;
        const uint32_t middle = low + ((high - low) / 2);
        if (t->rows[middle].address <= address) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }

    if (low == 0) return false;
    *out = low - 1;
    dwarf_assert_hot(*out < t->rows_count);
    return true;
}

static bool row_matches(const struct dwarf *d, const struct dwarf_line_table *t,
                        const struct dwarf_line_row *row, const char *path,
                        uint32_t line) {
    dwarf_assert_hot(row != NULL);
    dwarf_assert_hot(path != NULL);

    if (row->line != line) return false;
    // A non-statement row is mid-expression, which is no place for a breakpoint.
    if ((row->flags & dwarf_line_flag_statement) == 0) return false;
    if ((row->flags & dwarf_line_flag_end_sequence) != 0) return false;
    if (row->file >= t->files_count) return false;

    const char *const directory = dwarf_string(d, t->files[row->file].directory);
    const char *const file = dwarf_string(d, t->files[row->file].name);
    return path_matches(directory, file, path);
}

// A relative query must land on a separator, or "er/x.c" would match "/other/x.c".
static bool path_matches(const char *directory, const char *file, const char *query) {
    dwarf_assert_hot(query != NULL);
    if (file == NULL) return false;

    const char *const slash = strrchr(query, '/');
    if (slash == NULL) return strcmp(query, file) == 0;
    if (strcmp(slash + 1, file) != 0) return false;
    if (directory == NULL) return false;

    const size_t query_bytes = (size_t)(slash - query);
    const size_t directory_bytes = strlen(directory);
    if (query_bytes > directory_bytes) return false;

    const char *const tail = directory + (directory_bytes - query_bytes);
    if (strncmp(tail, query, query_bytes) != 0) return false;
    if (query_bytes == directory_bytes) return true;
    return directory[directory_bytes - query_bytes - 1] == '/';
}

static void line_info(const struct dwarf *d, const struct dwarf_line_table *t, uint32_t row,
                      struct dwarf_line_info *out) {
    dwarf_assert_hot(d != NULL);
    dwarf_assert_hot(row < t->rows_count);
    dwarf_assert_hot(out != NULL);

    const struct dwarf_line_row *const entry = &t->rows[row];
    *out = (struct dwarf_line_info){ .address = entry->address, .line = entry->line };
    if (entry->file >= t->files_count) return;

    out->directory = dwarf_string(d, t->files[entry->file].directory);
    out->file = dwarf_string(d, t->files[entry->file].name);
}
