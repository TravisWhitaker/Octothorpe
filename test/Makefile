# libocto Copyright (C) Travis Whitaker 2013

# libocto is developed with clang:
CC=clang
CFLAGS= -Wall -Wextra -Werror -pedantic -O2 -pipe -march=native
DEBUG_CFLAGS= -Wall -Wextra -Werror -pedantic -O0 -g -pipe -DDEBUG_MSG_ENABLE
INCLUDE= -I../include
LFLAGS = -L../ -locto

.PHONY: all
all: carry_test
	./carry_test

carry_test: test_carry.c
	$(CC) $(INCLUDE) -o carry_test  $(CFLAGS) test_carry.c $(LFLAGS)

.PHONY: debug
debug: carry_test_debug
	./carry_test_debug

carry_test_debug: test_carry.c
	$(CC) $(INCLUDE) -o carry_test_debug $(CFLAGS) test_carry.c -L../ -loctodebug

.PHONY: clean
clean:
	rm -f *.o*
	rm -f *_test*
