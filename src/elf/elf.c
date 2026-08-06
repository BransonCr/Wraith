// Wraith's objectfile layer. Bytes in, structs out
#include <elf/elf.h>

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

//helper functions
static int elf_map(int descriptor, const char *path, struct elf *e);
static int elf_parse(struct elf *e, const char *path);
static int elf_parse_sections(struct elf *e, const char *path);
static void elf_parse_symbols(struct elf *e);
static const Elf64_Shdr *elf_section_containing(const struct elf *e, uint64_t address_file);
static const char *elf_string(const struct elf *e, const Elf64_Shdr *table, uint32_t offset);

// Syscall budget: 4 (open, fstat, mmap, close).
// Allocation: none. mmap is not the heap, and elf_close returns the region.
int elf_open(const char *path, struct elf *e) {
    assert(path != NULL);
    assert(e != NULL);

    *e = (struct elf){0};

    const int descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (descriptor == -1) {
        perror(path);
        return -1;
    }

    const int result = elf_map(descriptor, path, e);


    if (close(descriptor) == -1) perror("close");
    return result;
}

void elf_close(struct elf *e) {
    assert(e != NULL);

    if (e->data != NULL) {
        assert(e->size_bytes > 0);
        if (munmap((void *)(uintptr_t)e->data, (size_t)e->size_bytes) == -1) {
            perror("munmap");
        }
    } else {
        assert(e->size_bytes == 0);  // The negative space: no map, no size.
    }
    *e = (struct elf){0};
}

uint64_t elf_entry(const struct elf *e) {
    assert(e != NULL);
    assert(e->header != NULL);

    return e->header->e_entry;
}

const char *elf_section_name(const struct elf *e, uint32_t index) {
    assert(e != NULL);
    assert(index < e->sections_count);

    if (e->section_strings == NULL) return NULL;
    return elf_string(e, e->section_strings, e->sections[index].sh_name);
}
bool elf_section_bytes(const struct elf *e, const char *name,
                        const uint8_t **data_out, uint64_t *size_bytes_out) {
    assert(e != NULL);
    assert(name != NULL);
    assert(data_out != NULL);
    assert(size_bytes_out != NULL);

    *data_out = NULL;
    *size_bytes_out = 0;

    for (uint32_t i = 0; i < e->sections_count; i++) {
        const Elf64_Shdr *const section = &e->sections[i];
        if (section->sh_type == SHT_NOBITS) continue;

        const char *const found = elf_section_name(e, i);
        if (found == NULL) continue;
        if (strcmp(found, name) != 0) continue;

        if (section->sh_offset > e->size_bytes) return false;
        if (section->sh_size > e->size_bytes - section->sh_offset) return false;

        *data_out = e->data + section->sh_offset;
        *size_bytes_out = section->sh_size;
        return true;
    }
    return false;
}
bool elf_address_file(const struct elf *e, uint64_t load_bias,
                      uint64_t address_virtual, uint64_t *out) {
    assert(e != NULL);
    assert(out != NULL);

    if (address_virtual < load_bias) return false;  // Below the image entirely.

    const uint64_t address_file = address_virtual - load_bias;
    if (elf_section_containing(e, address_file) == NULL) return false;

    *out = address_file;
    return true;
}

bool elf_address_virtual(const struct elf *e, uint64_t load_bias,
                         uint64_t address_file, uint64_t *out) {
    assert(e != NULL);
    assert(out != NULL);

    if (elf_section_containing(e, address_file) == NULL) return false;

    *out = address_file + load_bias;
    return true;
}


// Upgrade trigger: this runs once per stop over a few dozen symbols. A sorted
// address array and a binary search (8.1) become the right shape the moment it
// runs per instruction, or the table reaches thousands of entries.
const Elf64_Sym *elf_symbol_containing(const struct elf *e, uint64_t address_file) {
    assert(e != NULL);
    assert(e->symbols_count == 0 || e->symbols != NULL);

    for (uint32_t index = 0; index < e->symbols_count; index++) {
        const Elf64_Sym *const symbol = &e->symbols[index];

        if (symbol->st_shndx == SHN_UNDEF) continue;  // Defined in another object.
        if (symbol->st_size == 0) continue;
        if (ELF64_ST_TYPE(symbol->st_info) == STT_TLS) continue;  // Offset, not address.

        // Low side first: subtracting below the start wraps to near 2^64, and a
        // bounds check written the other way round would pass.
        if (address_file < symbol->st_value) continue;
        if (address_file - symbol->st_value >= symbol->st_size) continue;
        return symbol;
    }
    return NULL;
}


const Elf64_Sym *elf_symbol_by_name(const struct elf *e, const char *name) {
    assert(e != NULL);
    assert(name != NULL);

    for (uint32_t index = 0; index < e->symbols_count; index++) {
        const char *const candidate = elf_symbol_name(e, &e->symbols[index]);
        if (candidate == NULL) continue;
        if (strcmp(candidate, name) == 0) return &e->symbols[index];
    }
    return NULL;
}

const char *elf_symbol_name(const struct elf *e, const Elf64_Sym *symbol) {
    assert(e != NULL);
    assert(symbol != NULL);

    if (e->symbol_strings == NULL) return NULL;  // Stripped: nothing has a name.
    return elf_string(e, e->symbol_strings, symbol->st_name);
}

static int elf_map(int descriptor, const char *path, struct elf *e) {
    assert(descriptor >= 0);
    assert(path != NULL);
    assert(e != NULL);

    struct stat status;
    if (fstat(descriptor, &status) == -1) {
        perror("fstat");
        return -1;
    }
    if (status.st_size < (off_t)sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "%s: shorter than an ELF header\n", path);
        return -1;
    }

    // MAP_PRIVATE rather than sdb's MAP_SHARED. Neither can write through a
    // PROT_READ mapping
    void *const mapping = mmap(NULL, (size_t)status.st_size, PROT_READ, MAP_PRIVATE,
                               descriptor, 0);
    if (mapping == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    e->data = (const uint8_t *)mapping;
    e->size_bytes = (uint64_t)status.st_size;

    if (elf_parse(e, path) == -1) {
        elf_close(e);
        return -1;
    }
    return 0;
}

static int elf_parse(struct elf *e, const char *path) {
    assert(e != NULL);
    assert(e->data != NULL);
    assert(e->size_bytes >= sizeof(Elf64_Ehdr));

    const Elf64_Ehdr *const header = (const Elf64_Ehdr *)e->data;

    // Everything below trusts these fields, and the file came from the user, so
    // they are checked one at a time before anything is believed.
    if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "%s: not an ELF file\n", path);
        return -1;
    }
    if (header->e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "%s: not a 64-bit object\n", path);
        return -1;
    }
    if (header->e_ident[EI_DATA] != ELFDATA2LSB) {
        fprintf(stderr, "%s: not little-endian\n", path);
        return -1;
    }
    if (header->e_machine != EM_X86_64) {
        fprintf(stderr, "%s: not x86-64\n", path);
        return -1;
    }

    e->header = header;
    if (elf_parse_sections(e, path) == -1) return -1;
    elf_parse_symbols(e);
    return 0;
}

static int elf_parse_sections(struct elf *e, const char *path) {
    assert(e != NULL);
    assert(e->header != NULL);

    const Elf64_Ehdr *const header = e->header;
    if (header->e_shoff == 0) return 0;  // No section headers at all; still valid.

    if (header->e_shentsize != sizeof(Elf64_Shdr)) {
        fprintf(stderr, "%s: section headers are %u bytes\n", path, header->e_shentsize);
        return -1;
    }

    if (header->e_shoff % _Alignof(Elf64_Shdr) != 0) {
        fprintf(stderr, "%s: section header table is misaligned\n", path);
        return -1;
    }
    if (header->e_shoff > e->size_bytes) {
        fprintf(stderr, "%s: section header table starts past the end\n", path);
        return -1;
    }
    if (e->size_bytes - header->e_shoff < sizeof(Elf64_Shdr)) {
        fprintf(stderr, "%s: section header table is truncated\n", path);
        return -1;
    }

    const Elf64_Shdr *const sections = (const Elf64_Shdr *)(e->data + header->e_shoff);
.
    uint32_t count = header->e_shnum;
    if (count == 0) count = (uint32_t)sections[0].sh_size;

    uint32_t strings_index = header->e_shstrndx;
    if (strings_index == SHN_XINDEX) strings_index = sections[0].sh_link;

    if ((uint64_t)count * sizeof(Elf64_Shdr) > e->size_bytes - header->e_shoff) {
        fprintf(stderr, "%s: section header table runs past the end\n", path);
        return -1;
    }

    e->sections = sections;
    e->sections_count = count;
    if (strings_index < count) e->section_strings = &sections[strings_index];
    return 0;
}


static void elf_parse_symbols(struct elf *e) {
    assert(e != NULL);
    assert(e->sections_count == 0 || e->sections != NULL);

    for (uint32_t index = 0; index < e->sections_count; index++) {
        const Elf64_Shdr *const section = &e->sections[index];
        if (section->sh_type != SHT_SYMTAB) continue;
        if (section->sh_entsize != sizeof(Elf64_Sym)) continue;
        if (section->sh_offset % _Alignof(Elf64_Sym) != 0) continue;
        if (section->sh_offset > e->size_bytes) continue;
        if (section->sh_size > e->size_bytes - section->sh_offset) continue;

        e->symbols = (const Elf64_Sym *)(e->data + section->sh_offset);
        e->symbols_count = (uint32_t)(section->sh_size / section->sh_entsize);

        // sh_link names this table's own string table. Assuming ".strtab"
        // happens to work on today's binaries; the field is the actual answer.
        if (section->sh_link < e->sections_count) {
            e->symbol_strings = &e->sections[section->sh_link];
        }
        return;
    }
}

static const Elf64_Shdr *elf_section_containing(const struct elf *e, uint64_t address_file) {
    assert(e != NULL);
    assert(e->sections_count == 0 || e->sections != NULL);

    for (uint32_t index = 0; index < e->sections_count; index++) {
        const Elf64_Shdr *const section = &e->sections[index];
        if ((section->sh_flags & SHF_ALLOC) == 0) continue;
        if (address_file < section->sh_addr) continue;
        if (address_file - section->sh_addr >= section->sh_size) continue;
        return section;
    }
    return NULL;
}


static const char *elf_string(const struct elf *e, const Elf64_Shdr *table, uint32_t offset) {
    assert(e != NULL);
    assert(table != NULL);

    if (table->sh_offset > e->size_bytes) return NULL;
    if (table->sh_size > e->size_bytes - table->sh_offset) return NULL;
    if (offset >= table->sh_size) return NULL;

    const char *const strings = (const char *)(e->data + table->sh_offset);

    if (strings[table->sh_size - 1] != '\0') return NULL;
    return strings + offset;
}
