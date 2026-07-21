CC = cc
CFLAGS = -Wall -Wextra -std=c11 -Iinclude
SRCS = $(wildcard src/*.c)

wraith: $(SRCS)
	$(CC) $(CFLAGS) -o wraith $(SRCS)
run: wraith
	./wraith

clean:
	rm -f wraith

.PHONY: run clean
