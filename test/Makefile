# libocto Copyright (C) Travis Whitaker 2013

# libocto is developed with clang:
CC=clang
CFLAGS= -Wall -Wextra -Werror -pedantic -O2 -pipe -march=native
DEBUG_CFLAGS= -Wall -Wextra -Werror -pedantic -O0 -g -pipe -DDEBUG_MSG_ENABLE
INCLUDE= -I../include
LFLAGS = -L../ -locto

.PHONY: all
all: keygen_test carry_test
	./keygen_test
	./carry_test
	./cll_test

keygen_test: test_keygen.c
	$(CC) $(INCLUDE) -o keygen_test $(CFLAGS) test_keygen.c $(LFLAGS)

carry_test: test_carry.c
	$(CC) $(INCLUDE) -o carry_test  $(CFLAGS) test_carry.c $(LFLAGS)

cll_test: test_cll.c
	$(CC) $(INCLUDE) -o cll_test $(CFLAGS) test_cll.c $(LFLAGA)

.PHONY: debug
debug: keygen_test_debug carry_test_debug cll_test_debug
	./keygen_test_debug
	./carry_test_debug
	./cll_test_debug

keygen_test_debug: test_keygen.c
	$(CC) $(INCLUDE) -o keygen_test_debug $(CFLAGS) test_keygen.c -L../ -loctodebug

carry_test_debug: test_carry.c
	$(CC) $(INCLUDE) -o carry_test_debug $(CFLAGS) test_carry.c -L../ -loctodebug

cll_test_debug: test_cll.c
	$(CC) $(INCLUDE) -o cll_test_debug $(CFLAGS) test_cll.c -L../ -loctodebug

.PHONY: clean
clean:
	rm -f *.o
	rm -f *.o.debug
	rm -f *_test*
