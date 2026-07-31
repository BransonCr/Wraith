#ifndef WRAITH_REGISTERS_H_
#define WRAITH_REGISTERS_H_

#include <assert.h>
#include <stdint.h>
#include <sys/user.h>

enum register_area {
    REGISTER_AREA_GENERAL,
    REGISTER_AREA_FLOAT,
    REGISTER_AREA_DEBUG,
};

enum register_format {
    REGISTER_FORMAT_INTEGER,
    REGISTER_FORMAT_DOUBLE,
    REGISTER_FORMAT_VECTOR,
};


struct register_info {
    const char *name;
    uint16_t offset_bytes;
    uint8_t size_bytes;
    uint8_t dwarf_id;
    uint8_t area;
};

static_assert(sizeof(struct register_info) == 16, "register_info is too big; must be 16 bytes");

struct register_value {
    union {
        uint64_t integer;
        double floating;
        uint8_t bytes[16]; // xmm0-xmm15, and the 10 significant bytes of st0-7
    };
    uint8_t format;
    uint8_t size_bytes;
};

static_assert(sizeof(struct register_value) == 24, "16 payload + 2 tag + padding");

enum { WRAITH_REGISTER_COUNT = 18};
enum { WRAITH_REGISTER_DWARF_NONE = 0xFF };
extern const struct register_info register_table[];


const struct register_info *register_by_name(const char *name);
const struct register_info *register_by_dwarf_id(uint8_t dwarf_id);
void register_read(const struct user_regs_struct *registers,
                   const struct register_info *info,
                   struct register_value *out);

void register_write(struct user_regs_struct *registers,
                    const struct register_info *info,
                    uint64_t value);

#endif // WRAITH_REGISTERS_H_
