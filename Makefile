CC = cc
CFLAGS = -Wall -Wextra -std=gnu11 -Iinclude

SRCS = $(wildcard src/*.c)

# The test binary links every module except src/main.c, because
# tests/test_process.c brings its own main().
LIB_SRCS = $(filter-out src/main.c,$(SRCS))
TEST_SRCS = $(wildcard tests/*.c)

# The default target builds the debugger and then runs the suite. A binary that
# compiles but fails its own tests is not a build, so `make` refuses to finish:
# a failed assert aborts with a non-zero status and make stops here.
all: wraith test

wraith: $(SRCS)
	$(CC) $(CFLAGS) -o wraith $(SRCS)

wraith_test_process: tests/test_process.c $(LIB_SRCS)
	$(CC) $(CFLAGS) -o $@ $^

wraith_test_registers: tests/test_registers.c $(LIB_SRCS)
	$(CC) $(CFLAGS) -o $@ $^

test: wraith_test_process wraith_test_registers
	./wraith_test_process
	./wraith_test_registers

run: wraith
	./wraith


clean:
	rm -f wraith wraith_test

.PHONY: all test run clean
