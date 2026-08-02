// The syscall table is generated, so what needs testing is not the data but the
// two lookups over it: that a number maps back to its name, that a name maps
// back to its number, and that neither one walks into the hole in the middle of
// the numbering.
#include <syscall.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    // Both directions, at a number small enough to be found before the hole.
    assert(strcmp(syscall_name(0), "read") == 0);
    assert(strcmp(syscall_name(1), "write") == 0);

    uint16_t number = 0;
    assert(syscall_number("read", &number));
    assert(number == 0);
    assert(syscall_number("kill", &number));
    assert(number == 62);

    // Past the hole at 337 to 423. A lookup reaching here has already walked
    // every NULL slot, which is the crash this test exists to prevent.
    assert(syscall_number("landlock_add_rule", &number));
    assert(number == 445);
    assert(strcmp(syscall_name(445), "landlock_add_rule") == 0);

    // The negative space: a hole, a number past the end, and a name that is not
    // a syscall. A miss walks the whole table, so it is the longest scan there
    // is and the one most likely to fault.
    assert(syscall_name(337) == NULL);
    assert(syscall_name(65535) == NULL);
    assert(!syscall_number("writee", &number));
    assert(!syscall_number("", &number));

    // A failed lookup must leave the caller's variable alone, or a rejected
    // name silently becomes whatever was there before.
    number = 4242;
    assert(!syscall_number("not_a_syscall", &number));
    assert(number == 4242);

    printf("test_syscall: all tests passed\n");
    return 0;
}
