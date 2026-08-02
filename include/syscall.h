#ifndef WRAITH_SYSCALL_H_
#define WRAITH_SYSCALL_H_

#include <stdbool.h>
#include <stdint.h>

// Syscall number against syscall name, for x86-64 Linux

// Syscall budget: 0.
// Allocation: none. The returned string is static storage.
const char *syscall_name(uint16_t number);

// Syscall budget: 0.
// Allocation: none.
bool syscall_number(const char *name, uint16_t *out);

#endif  // WRAITH_SYSCALL_H_
