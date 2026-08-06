#include "arena/arena.h"

#include <assert.h>
#include <stddef.h>
#include <sys/mman.h>

int arena_init(struct arena *a, uint64_t size_bytes) {
    assert(a != NULL);
    assert(size_bytes > 0);

    void *const base = mmap(NULL, (size_t)size_bytes, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (base == MAP_FAILED) return -1;

    *a = (struct arena){
        .base = base,
        .size_bytes = size_bytes,
        .offset_bytes = 0,
    };

    assert(a->base != NULL);
    assert(a->offset_bytes == 0);
    return 0;
}

void arena_deinit(struct arena *a) {
    assert(a != NULL);
    if (a->base == NULL) return;

    const int result = munmap(a->base, (size_t)a->size_bytes);
    assert(result == 0);
    (void)result;

    *a = (struct arena){0};
    assert(a->base == NULL);
}

void *arena_alloc(struct arena *a, uint64_t size_bytes, uint64_t alignment_bytes) {
    assert(a != NULL);
    assert(a->base != NULL);
    assert(size_bytes > 0);
    assert(alignment_bytes > 0);
    // A power of two is what makes the mask below a valid rounding step.
    assert((alignment_bytes & (alignment_bytes - 1)) == 0);
    assert(a->offset_bytes <= a->size_bytes);

    const uint64_t mask = alignment_bytes - 1;
    const uint64_t start = (a->offset_bytes + mask) & ~mask;

    // Both checks are written against the remaining space rather than against
    // the sum, because the sum is the thing that would overflow.
    if (start > a->size_bytes) return NULL;
    if (size_bytes > a->size_bytes - start) return NULL;

    a->offset_bytes = start + size_bytes;

    assert(a->offset_bytes <= a->size_bytes);
    return a->base + start;
}
