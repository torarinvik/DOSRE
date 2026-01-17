CC ?= cc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Wpedantic

all: reasm_from_comments

reasm_from_comments: reasm_from_comments.c reasm_from_comments_lib.c reasm_from_comments_lib.h
	$(CC) $(CFLAGS) -o $@ reasm_from_comments.c reasm_from_comments_lib.c

clean:
	rm -f reasm_from_comments

.PHONY: all clean
