#ifndef WRAITH_ELF_ELF_H_
#define WRAITH_ELF_ELF_H_

#include <assert.h>
#include <elf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdbool.h>

//
// Nothing is copied out of the file. Every pointer aims into the mapping, so a
// binary with a megabyte of symbols costs one mmap and the pages actually read.
struct elf {
    const uint8_t *data;
    const Elf64_Ehdr *header;
    const Elf64_Shdr *sections;
    const Elf64_Shdr *section_strings;
    const Elf64_Shdr *symbol_strings;
    const Elf64_Sym *symbols;
    uint64_t size_bytes;
    uint32_t sections_count;
    uint32_t symbols_count;
};

static_assert(sizeof(struct elf) == 64, "six pointers and three counts, one cache line");

int elf_open(const char *path, struct elf *e);
void elf_close(struct elf *e);

uint64_t elf_entry(const struct elf *e);
const char *elf_section_name(const struct elf *e, uint32_t index);
bool elf_section_bytes(const struct elf *e, const char *name,
                       const uint8_t **data_out, uint64_t *size_bytes_out);
// Guarded by the section table on purpose: an address on the stack belongs to
// no section of this file, and shifting it by the bias would otherwise produce
// a file address that can land inside a  symbol by coincidence.
bool elf_address_file(const struct elf *e, uint64_t load_bias,
                      uint64_t address_virtual, uint64_t *out);
bool elf_address_virtual(const struct elf *e, uint64_t load_bias,
                         uint64_t address_file, uint64_t *out);

// Syscall budget: 0.
// Allocation: none. The result aims into the mapping and dies with elf_close.
const Elf64_Sym *elf_symbol_containing(const struct elf *e, uint64_t address_file);
const Elf64_Sym *elf_symbol_by_name(const struct elf *e, const char *name);
const char *elf_symbol_name(const struct elf *e, const Elf64_Sym *symbol);

#endif  // WRAITH_ELF_ELF_H_
