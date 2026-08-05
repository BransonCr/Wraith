#ifndef WRAITH_DISASSEMBLER_H_
#define WRAITH_DISASSEMBLER_H_

#include <assert.h>
#include <stdint.h>

// The architectural maximum length of one x86-64 instruction. A caller wanting
// n instructions must therefore supply n * 15
enum { disassembler_instruction_size_bytes_max = 15 };

// Matches Zydis's own formatting buffer exactly.
enum { disassembler_text_size_bytes_max = 96 };

struct disassembler_instruction {
    uint64_t address;
    char text[disassembler_text_size_bytes_max];
    uint8_t size_bytes;
};

static_assert(sizeof(struct disassembler_instruction) == 112,
              "8 address + 96 text + 1 length, rounded up to the 8-byte alignment");

// Syscall budget: 0.
// Allocation: none. The caller owns *out.
uint32_t disassembler_decode(const uint8_t *bytes, uint32_t size_bytes, uint64_t address,
                             struct disassembler_instruction *out, uint32_t count_max);

#endif  // WRAITH_DISASSEMBLER_H_
