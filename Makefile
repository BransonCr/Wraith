CC = cc
CFLAGS = -Wall -Wextra -std=c11

wraith: src/main.c
	$(CC) $(CFLAGS) -o wraith src/main.c
run: wraith
	./wraith

clean:
	rm -f wraith

.PHONY: run clean
