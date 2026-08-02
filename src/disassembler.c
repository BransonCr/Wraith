// Wraith's disassembly layer: bytes in, instructions out.
//
// It knows x86-64 encoding and nothing else. No pid, no ptrace, no breakpoints
//  the caller has already read the memory and already painted the saved bytes
// back over any armed traps, so what arrives here is the program as written.
//
//
#include <assert.h>
#include <string.h>

#include <disassembler.h>
#include <Zydis/Zydis.h>

uint32_t disassembler_decode(const uint8_t *bytes, uint32_t size_bytes, uint64_t address,
                             struct disassembler_instruction *out, uint32_t count_max) {

    assert(bytes != NULL);
    assert(out != NULL);
    assert(count_max > 0);
    assert(size_bytes > 0);

    uint32_t offset = 0;
    uint32_t count = 0;

    while (count < count_max) {
        if (offset >= size_bytes)  break;

        // 1232 bytes, so it stays a local and is never passed or returned by
        // value. Only two of its fields are ever read.
        ZydisDisassembledInstruction instruction;
        const ZyanStatus status =
            ZydisDisassembleATT(ZYDIS_MACHINE_MODE_LONG_64, address + offset, bytes + offset,
                                size_bytes - offset, &instruction);


        // AT&T rather than Intel so the output diffs directly against objdump,
        // which is the oracle this layer is verified against.

        if (!ZYAN_SUCCESS(status)) break;

        assert(instruction.info.length > 0);
        assert(instruction.info.length <= disassembler_instruction_size_bytes_max);

        out[count] = (struct disassembler_instruction) {
            .address = address + offset,
            .size_bytes = instruction.info.length,
        };

        memcpy(out[count].text, instruction.text, sizeof out[count].text);
        assert(out[count].text[sizeof out[count].text -1] == '\0');

        offset += instruction.info.length;
        count++;
    }

    assert(count <= count_max);
    assert(offset <= size_bytes);
    return count;
}
