// The ELF layer is pure — bytes in, structs out, no tracee — so this test
// parses the fixture the Makefile builds beside it and checks both lookups
// against numbers readelf will confirm by hand. Method: find a symbol by name,
// then use its own st_value and st_size to probe the address lookup from the
// inside, from the edge, and from one byte past the end.
#include <elf/elf.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    struct elf elf;
    assert(elf_open("./target", &elf) == 0);

    // The file's symbol table must agree with the file's own header.
    const Elf64_Sym *const start = elf_symbol_by_name(&elf, "_start");
    assert(start != NULL);
    assert(start->st_value == elf_entry(&elf));

    // main has a real size, so containment finds it from the inside.
    const Elf64_Sym *const main_symbol = elf_symbol_by_name(&elf, "main");
    assert(main_symbol != NULL);
    assert(main_symbol->st_size > 0);

    const Elf64_Sym *const found = elf_symbol_containing(&elf, main_symbol->st_value + 1);
    assert(found == main_symbol);
    const char *const found_name = elf_symbol_name(&elf, found);
    assert(found_name != NULL);
    assert(strcmp(found_name, "main") == 0);

    // The negative space: both edges of the range, and a name that is not one.
    assert(elf_symbol_containing(&elf, main_symbol->st_value) == main_symbol);
    const uint64_t past = main_symbol->st_value + main_symbol->st_size;
    assert(elf_symbol_containing(&elf, past) != main_symbol);
    assert(elf_symbol_by_name(&elf, "not_a_symbol") == NULL);

    // A zero-size symbol contains nothing. This is the documented divergence
    // from gdb, which stretches such a symbol to the next symbol's address, so
    // it is asserted rather than discovered later against the oracle.
    const Elf64_Sym *const fini = elf_symbol_by_name(&elf, "_fini");
    assert(fini != NULL);
    assert(fini->st_size == 0);
    assert(elf_symbol_containing(&elf, fini->st_value) == NULL);

    // The bias round trip. Zero is the -no-pie case and must be the identity.
    uint64_t address_file = 0;
    assert(elf_address_file(&elf, 0, main_symbol->st_value, &address_file));
    assert(address_file == main_symbol->st_value);

    uint64_t address_virtual = 0;
    assert(elf_address_virtual(&elf, 0x1000, main_symbol->st_value, &address_virtual));
    assert(address_virtual == main_symbol->st_value + 0x1000);
    assert(elf_address_file(&elf, 0x1000, address_virtual, &address_file));
    assert(address_file == main_symbol->st_value);

    // An address in no section of this file — every stack and heap address is
    // one. Without this guard the subtraction produces a file address that can
    // land inside a real symbol by coincidence.
    assert(!elf_address_file(&elf, 0, 0x7fff00000000ULL, &address_file));

    elf_close(&elf);
    assert(elf_symbol_by_name(&elf, "main") == NULL);  // Closed means empty.

    printf("test_elf: all tests passed\n");
    return 0;
}
