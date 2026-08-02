CC = cc
CFLAGS = -Wall -Wextra -std=gnu11 -Iinclude

LDLIBS = -lZydis

SRCS = $(wildcard src/*.c)

# The test binaries link every module except src/main.c, because each test file
# brings its own main().
LIB_SRCS = $(filter-out src/main.c,$(SRCS))

TESTS = wraith_test_process wraith_test_registers wraith_test_control wraith_test_syscall

all: wraith test

wraith: $(SRCS)
	$(CC) $(CFLAGS) -o wraith $(SRCS) $(LDLIBS)

wraith_test_process: tests/test_process.c $(LIB_SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

wraith_test_registers: tests/test_registers.c $(LIB_SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

wraith_test_control: tests/test_control.c $(LIB_SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

wraith_test_syscall: tests/test_syscall.c $(LIB_SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

test: $(TESTS)
	@for binary in $(TESTS); do ./$$binary || exit 1; done

clean:
	rm -f wraith $(TESTS)

run: wraith
	./wraith

.PHONY: all test run clean
