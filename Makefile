CC = cc
CFLAGS = -Wall -Wextra -std=gnu11 -Iinclude

# Zydis ships no pkg-config file — verified against 4.1.1, which installs
# lib/cmake/ and no lib/pkgconfig/, so `pkg-config --exists zydis` fails. Its
# headers land straight in /usr/include, so there is nothing to add to CFLAGS,
# and libZydis.so already carries libZycore.so as DT_NEEDED, so one -l is enough.
# Install with: pacman -S zydis
LDLIBS = -lZydis

SRCS = $(wildcard src/*.c)

# The test binaries link every module except src/main.c, because each test file
# brings its own main().
LIB_SRCS = $(filter-out src/main.c,$(SRCS))

# The default target builds the debugger and then runs the suite. A binary that
# compiles but fails its own tests is not a build, so `make` refuses to finish:
# a failed assert aborts with a non-zero status and make stops here.
all: wraith test

wraith: $(SRCS)
	$(CC) $(CFLAGS) -o wraith $(SRCS) $(LDLIBS)

wraith_test_process: tests/test_process.c $(LIB_SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

wraith_test_registers: tests/test_registers.c $(LIB_SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

wraith_test_control: tests/test_control.c $(LIB_SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

test: wraith_test_process wraith_test_registers wraith_test_control
	./wraith_test_process
	./wraith_test_registers
	./wraith_test_control

clean:
	rm -f wraith wraith_test_process wraith_test_registers wraith_test_control

run: wraith
	./wraith

.PHONY: all test run clean
