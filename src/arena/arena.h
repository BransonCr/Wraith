#ifndef WRAITH_ARENA_ARENA_H_
#define WRAITH_ARENA_ARENA_H_

#include <assert.h>
#include <stdint.h>

struct arena {
    uint8_t *base;
    uint64_t size_bytes;
    uint64_t offset_bytes;
};

static_assert(sizeof(struct arena) == 24, "one pointer and two counts");

int arena_init(struct arena *a, uint64_t size_bytes);
void arena_deinit(struct arena *a);

void *arena_alloc(struct arena *a, uint64_t size_bytes, uint64_t alignment_bytes);

#endif  // WRAITH_ARENA_ARENA_H_
