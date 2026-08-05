CC = cc
CFLAGS = -Wall -Wextra -std=gnu11 -Isrc

LDLIBS = -lZydis

SRCS = src/main.c $(wildcard src/*/*.c)

# The test binaries link every module except src/main.c, because each test file
# brings its own main().
LIB_SRCS = $(filter-out src/main.c,$(SRCS))

TESTS = wraith_test_process wraith_test_registers wraith_test_control \
        wraith_test_syscall wraith_test_elf

all: wraith test

wraith: $(SRCS)
	$(CC) $(CFLAGS) -o wraith $(SRCS) $(LDLIBS)

# -no-pie fixes .text at a known address, so an address written down in one run
# is still valid in the next. -g keeps the symbol table chapter 11 exists to read.
target: target.c
	$(CC) -O0 -g -no-pie -o target target.c

wraith_test_process: tests/test_process.c $(LIB_SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

wraith_test_registers: tests/test_registers.c $(LIB_SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

wraith_test_control: tests/test_control.c $(LIB_SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

wraith_test_syscall: tests/test_syscall.c $(LIB_SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

# target is a prerequisite but not a source, so the sources are named rather
# than taken from $^ — $^ would hand the fixture binary to the compiler.
wraith_test_elf: tests/test_elf.c $(LIB_SRCS) target
	$(CC) $(CFLAGS) -o $@ tests/test_elf.c $(LIB_SRCS) $(LDLIBS)

test: $(TESTS)
	@for binary in $(TESTS); do ./$$binary || exit 1; done

clean:
	rm -f wraith target $(TESTS)

run: wraith
	./wraith

.PHONY: all test run clean
