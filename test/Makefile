# libocto Copyright (C) Travis Whitaker 2013

# libocto is developed with clang:
CC=clang
CFLAGS= -Wall -Wextra -Werror -pedantic -O2 -pipe -march=native
DEBUG_CFLAGS= -Wall -Wextra -Werror -pedantic -O0 -g -pipe -DDEBUG_MSG
INCLUDE= -I../include
LFLAGS = -L../ -locto

.PHONY: all
all: carry_test
	./carry_test

carry_test: test_carry.c
	$(CC) $(INCLUDE) -o carry_test  $(CFLAGS) test_carry.c $(LFLAGS)

.PHONY: clean
clean:
	rm -f *.o
	rm -f *_test
