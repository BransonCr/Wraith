#ifndef WRAITH_DWARF_DWARF_INTERNAL_H_
#define WRAITH_DWARF_DWARF_INTERNAL_H_

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef WRAITH_HOT_ASSERTS_OFF
#define dwarf_assert_hot(condition) ((void)0)
#else
#define dwarf_assert_hot(condition) assert(condition)
#endif

struct dwarf_cursor {
    const uint8_t *data;
    uint64_t size_bytes;
    uint64_t offset;
    bool overrun;
};

static inline const uint8_t *dwarf_cursor_bytes(struct dwarf_cursor *c, uint64_t count) {
    dwarf_assert_hot(c != NULL);
    dwarf_assert_hot(c->offset <= c->size_bytes);

    if (count > c->size_bytes - c->offset) {
        c->overrun = true;
        c->offset = c->size_bytes;
        return NULL;
    }
    const uint8_t *const start = c->data + c->offset;
    c->offset += count;
    return start;
}

// DWARF is little-endian on every target wraith supports, so one reader covers
// every fixed width and the width can come from a table rather than a branch.
static inline uint64_t dwarf_cursor_fixed(struct dwarf_cursor *c, uint32_t width_bytes) {
    dwarf_assert_hot(width_bytes >= 1);
    dwarf_assert_hot(width_bytes <= 8);

    const uint8_t *const bytes = dwarf_cursor_bytes(c, width_bytes);
    if (bytes == NULL) return 0;

    uint64_t value = 0;
    for (uint32_t i = 0; i < width_bytes; i++) {
        value |= (uint64_t)bytes[i] << (i * 8);
    }
    return value;
}

enum { dwarf_leb128_bytes_max = 10 };

static inline uint64_t dwarf_cursor_uleb128(struct dwarf_cursor *c) {
    dwarf_assert_hot(c != NULL);

    uint64_t value = 0;
    uint32_t shift = 0;
    for (uint32_t i = 0; i < dwarf_leb128_bytes_max; i++) {
        const uint8_t *const byte = dwarf_cursor_bytes(c, 1);
        if (byte == NULL) return 0;
        // Shifting a uint64_t by 64 or more is undefined, so the payload of a
        // byte past the top of the value is dropped rather than shifted in.
        if (shift < 64) value |= (uint64_t)(*byte & 0x7f) << shift;
        if ((*byte & 0x80) == 0) return value;
        shift += 7;
    }
    c->overrun = true;
    return 0;
}

static inline int64_t dwarf_cursor_sleb128(struct dwarf_cursor *c) {
    dwarf_assert_hot(c != NULL);

    uint64_t value = 0;
    uint32_t shift = 0;
    for (uint32_t i = 0; i < dwarf_leb128_bytes_max; i++) {
        const uint8_t *const byte = dwarf_cursor_bytes(c, 1);
        if (byte == NULL) return 0;
        if (shift < 64) value |= (uint64_t)(*byte & 0x7f) << shift;
        shift += 7;
        if ((*byte & 0x80) == 0) {
            // Sign extension runs on the unsigned value, because left-shifting
            // a negative signed integer is undefined in C.
            if (shift < 64) {
                if ((*byte & 0x40) != 0) value |= ~(uint64_t)0 << shift;
            }
            return (int64_t)value;
        }
    }
    c->overrun = true;
    return 0;
}


static inline const char *dwarf_cursor_string(struct dwarf_cursor *c) {
    dwarf_assert_hot(c != NULL);
    dwarf_assert_hot(c->offset <= c->size_bytes);

    const uint64_t start = c->offset;
    for (uint64_t i = start; i < c->size_bytes; i++) {
        if (c->data[i] == 0) {
            c->offset = i + 1;
            return (const char *)(c->data + start);
        }
    }
    c->overrun = true;
    c->offset = c->size_bytes;
    return NULL;
}

#endif  // WRAITH_DWARF_DWARF_INTERNAL_H_
