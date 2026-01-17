CC ?= cc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Wpedantic

all: bin16_dump_db

bin16_dump_db: bin16_dump_db.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f bin16_dump_db

.PHONY: all clean
