#ifndef WRAITH_REGISTERS_H_
#define WRAITH_REGISTERS_H_

#include <assert.h>     // static_assert
#include <stdint.h>

#include <sys/user.h>   // struct user_regs_struct

// Which of the kernel's register areas a row lives in. The area is stored, not
// inferred, because each one is reached differently: the general registers
// arrive in the GETREGSET that process.c already does per stop, floating point
// needs a second GETREGSET, and the debug registers are in neither — they come
// out of struct user one word at a time with PEEKUSER.
enum register_area {
    REGISTER_AREA_GENERAL,
    REGISTER_AREA_FLOAT,
    REGISTER_AREA_DEBUG,
};

// How to print the bytes once you have them. The bytes alone do not say
// whether 0x4008000000000000 is an integer or the double 3.0.
enum register_format {
    REGISTER_FORMAT_INTEGER,
    REGISTER_FORMAT_DOUBLE,
    REGISTER_FORMAT_VECTOR,
};

// Rows with no DWARF number: every sub-register (eax, ax, al, ah) and every
// debug register. Real x86-64 DWARF numbers stop at 66, so 0xFF is free, and
// this is the same 0xFF-means-none idiom as bp_entry.dr_slot in PERFORMANCE.md.
enum { WRAITH_REGISTER_DWARF_NONE = 0xFF };

// One row of the register table: a name the user can type, plus the three facts
// needed to find its bytes.
//
// INVARIANT: offset_bytes + size_bytes <= sizeof the struct named by area.
// INVARIANT: size_bytes is 1, 2, 4, 8, or 16.
// INVARIANT: dwarf_id is unique across the table, or WRAITH_REGISTER_DWARF_NONE.
struct register_info {
    const char *name;       // "rax", "eax", "al". Points into .rodata, never freed.
    uint16_t offset_bytes;  // Offset into the area, from offsetof.
    uint8_t  size_bytes;    // How wide this name's window onto the register is.
    uint8_t  dwarf_id;      // Or WRAITH_REGISTER_DWARF_NONE.
    uint8_t  area;          // enum register_area, held narrow to keep the row at 16.
};

// Descending field order plus the narrow area field keeps this at 16 bytes, so
// four rows land per cache line and a scan of the table reads it sequentially
// (4.1, 4.5). Widening a field is now a build failure rather than a slowdown.
static_assert(sizeof(struct register_info) == 16, "register_info must stay 16 bytes");

// A register's contents, copied out of a fetched block. Copied rather than
// pointed at, so the value stays readable after the next resume invalidates the
// cache. This is the tagged union that stands in for the book's std::variant
// (PERFORMANCE.md 2.3): one size for every case, so values live in flat arrays.
struct register_value {
    union {
        uint64_t integer;
        double   floating;
        uint8_t  bytes[16];  // xmm0-15, and the 10 significant bytes of st0-7.
    };
    uint8_t size_bytes;
    uint8_t format;          // enum register_format.
};

static_assert(sizeof(struct register_value) == 24, "16 payload + 2 tag + padding");

// The table lives in registers.c. Rows are in struct user_regs_struct field
// order, which is NOT DWARF order — DWARF calls rax 0, rdx 1, rcx 2, rbx 3,
// while the kernel struct starts at r15. That mismatch is the reason this table
// exists instead of a cast.
// INVARIANT: exactly WRAITH_REGISTER_COUNT rows, asserted in registers.c.
enum { WRAITH_REGISTER_COUNT = 18 };
extern const struct register_info register_table[];

// Finds the row the user's word names, or NULL when no register has that name.
// A linear scan: the caller is a human typing a command, so 18 strcmps are free,
// and a sorted table would add a second ordering invariant to maintain for a
// lookup that happens once per keystroke-driven command (8.4).
// Syscall budget: 0.
// Allocation: none.
const struct register_info *register_by_name(const char *name);

// The same lookup by DWARF number, for when debug info asks for register 6
// rather than for "rbp".
// Syscall budget: 0.
// Allocation: none.
const struct register_info *register_by_dwarf_id(uint8_t dwarf_id);

// Copies one general-purpose register out of an already-fetched block. Pure: no
// ptrace, which is why this header takes the block rather than a struct process.
// It keeps <sys/ptrace.h> confined to process.c, so the syscall budget of the
// whole program stays auditable in one file.
// Syscall budget: 0.
// Allocation: none. *out is filled in place.
void register_read(const struct user_regs_struct *registers,
                   const struct register_info *info,
                   struct register_value *out);

// Writes value into the caller's copy of the block, leaving every bit outside
// this register's window untouched. Writing al touches one byte at rax's own
// offset, because on a little-endian machine that is where the low byte is.
// Syscall budget: 0. Flushing the block to the tracee is process.c's job.
// Allocation: none.
void register_write(struct user_regs_struct *registers,
                    const struct register_info *info,
                    uint64_t value);

#endif  // WRAITH_REGISTERS_H_
