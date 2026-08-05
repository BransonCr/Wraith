#include <registers/registers.h>

#include <assert.h>   // assert
#include <stddef.h>   // offsetof
#include <string.h>   // memcpy, strcmp
                      //
const struct register_info register_table[] = {
    { "r15",    offsetof(struct user_regs_struct, r15),    8, 15, REGISTER_AREA_GENERAL },
    { "r14",    offsetof(struct user_regs_struct, r14),    8, 14, REGISTER_AREA_GENERAL },
    { "r13",    offsetof(struct user_regs_struct, r13),    8, 13, REGISTER_AREA_GENERAL },
    { "r12",    offsetof(struct user_regs_struct, r12),    8, 12, REGISTER_AREA_GENERAL },
    { "rbp",    offsetof(struct user_regs_struct, rbp),    8,  6, REGISTER_AREA_GENERAL },
    { "rbx",    offsetof(struct user_regs_struct, rbx),    8,  3, REGISTER_AREA_GENERAL },
    { "r11",    offsetof(struct user_regs_struct, r11),    8, 11, REGISTER_AREA_GENERAL },
    { "r10",    offsetof(struct user_regs_struct, r10),    8, 10, REGISTER_AREA_GENERAL },
    { "r9",     offsetof(struct user_regs_struct, r9),     8,  9, REGISTER_AREA_GENERAL },
    { "r8",     offsetof(struct user_regs_struct, r8),     8,  8, REGISTER_AREA_GENERAL },
    { "rax",    offsetof(struct user_regs_struct, rax),    8,  0, REGISTER_AREA_GENERAL },
    { "rcx",    offsetof(struct user_regs_struct, rcx),    8,  2, REGISTER_AREA_GENERAL },
    { "rdx",    offsetof(struct user_regs_struct, rdx),    8,  1, REGISTER_AREA_GENERAL },
    { "rsi",    offsetof(struct user_regs_struct, rsi),    8,  4, REGISTER_AREA_GENERAL },
    { "rdi",    offsetof(struct user_regs_struct, rdi),    8,  5, REGISTER_AREA_GENERAL },
    { "rip",    offsetof(struct user_regs_struct, rip),    8, 16, REGISTER_AREA_GENERAL },
    { "eflags", offsetof(struct user_regs_struct, eflags), 8, 49, REGISTER_AREA_GENERAL },
    { "rsp",    offsetof(struct user_regs_struct, rsp),    8,  7, REGISTER_AREA_GENERAL },
};


static_assert(sizeof(register_table) / sizeof(register_table[0]) == WRAITH_REGISTER_COUNT,
        "register_table must have exactly WRAITH_REGISTER_COUNT rows");


const struct register_info *register_by_name(const char *name) {
    assert(name != NULL);
    assert(name[0] != '\0');

    for (uint32_t i = 0; i < WRAITH_REGISTER_COUNT; i++) {
        assert(register_table[i].name != NULL);
        if (strcmp(register_table[i].name, name) == 0){
            return &register_table[i];
        }
    }
    return NULL; //not foudn

}

const struct register_info *register_by_dwarf_id(uint8_t dwarf_id) {
    // Asking for "the register with no DWARF number" is a category error: the
    // sentinel marks rows debug info can never name, so a hit would be a bug.
    assert(dwarf_id != WRAITH_REGISTER_DWARF_NONE);

    for (uint32_t i = 0; i < WRAITH_REGISTER_COUNT; i++) {
        assert(register_table[i].name != NULL);
        if (register_table[i].dwarf_id == dwarf_id) {
            return &register_table[i];
        }
    }
    return NULL;
}


void register_write(struct user_regs_struct *registers,
                    const struct register_info *info,
                    uint64_t value) {
    assert(registers != NULL);
    assert(info != NULL);
    assert(info->area == REGISTER_AREA_GENERAL);
    assert(info->size_bytes <= sizeof(value));
    assert((size_t)info->offset_bytes + info->size_bytes <= sizeof(*registers));

    // Copy the low size_bytes of value. On a little-endian machine those are
    // the first bytes of the object, which is exactly why writing al will be
    // able to reuse rax's own offset instead of needing an offset of its own.
    memcpy((uint8_t *)registers + info->offset_bytes, &value, info->size_bytes);
}


void register_read(const struct user_regs_struct *registers,
                   const struct register_info *info,
                   struct register_value *out) {
    assert(registers != NULL);
    assert(info != NULL);
    assert(out != NULL);
    assert(info->area == REGISTER_AREA_GENERAL);
    assert(info->size_bytes <= sizeof(out->integer));
    assert((size_t)info->offset_bytes + info->size_bytes <= sizeof(*registers));

    *out = (struct register_value){
        .size_bytes = info->size_bytes,
        .format = REGISTER_FORMAT_INTEGER,
    };

    // memcpy rather than castanddereference: the latter breaks strict
    // aliasing and assumes 8byte alignment. The sub register rows this table
    // is shaped for (ah, at rax+1) are not aligned. This compiles to one mov.
    memcpy(&out->integer, (const uint8_t *)registers + info->offset_bytes, info->size_bytes);
}
