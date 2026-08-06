#ifndef WRAITH_ARENA_ARENA_H_
#define WRAITH_ARENA_ARENA_H_

#include <assert.h>
#include <stdint.h>

// One reservation at startup, then allocating is a bounds check and an add.
// Nothing is freed individually; the region dies with the module that owns it.
// Reserving is not spending: MAP_NORESERVE pages cost address space until they
// are touched, so size_bytes is a ceiling rather than a cost. PERFORMANCE.md 3.1.
struct arena {
    uint8_t *base;
    uint64_t size_bytes;
    uint64_t offset_bytes;
};

static_assert(sizeof(struct arena) == 24, "one pointer and two counts");

int arena_init(struct arena *a, uint64_t size_bytes);
void arena_deinit(struct arena *a);

// Returns NULL when the reservation is exhausted. That is an operating error,
// not a bug: a binary larger than the ceiling is the user's problem.
// Syscall budget: 0.
// Allocation: bump only. No malloc.
void *arena_alloc(struct arena *a, uint64_t size_bytes, uint64_t alignment_bytes);

#endif  // WRAITH_ARENA_ARENA_H_
