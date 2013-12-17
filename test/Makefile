# libocto Copyright (C) Travis Whitaker 2013

# libocto is developed with clang:
CC=clang
CFLAGS= -Wall -Wextra -Werror -pedantic -O2 -pipe -march=native
DEBUG_CFLAGS= -Wall -Wextra -Werror -pedantic -O0 -g -pipe -DDEBUG_MSG_ENABLE
INCLUDE= -I../include
LFLAGS = -L../ -locto

.PHONY: all
all: keygen_test carry_test cll_test loa_test
	./keygen_test
	./carry_test
	./cll_test
	./loa_test

keygen_test: unit_keygen.c
	$(CC) $(INCLUDE) -o keygen_test $(CFLAGS) unit_keygen.c $(LFLAGS)

carry_test: unit_carry.c
	$(CC) $(INCLUDE) -o carry_test  $(CFLAGS) unit_carry.c $(LFLAGS)

cll_test: unit_cll.c
	$(CC) $(INCLUDE) -o cll_test $(CFLAGS) unit_cll.c $(LFLAGS)

loa_test: unit_loa.c
	$(CC) $(INCLUDE) -o loa_test $(CFLAGS) unit_loa.c $(LFLAGS)

.PHONY: debug
debug: keygen_unit_debug carry_unit_debug cll_unit_debug loa_unit_debug
	./keygen_unit_debug
	./carry_unit_debug
	./cll_unit_debug
	./loa_unit_debug

keygen_unit_debug: unit_keygen.c
	$(CC) $(INCLUDE) -o keygen_unit_debug $(CFLAGS) unit_keygen.c -L../ -loctodebug

carry_unit_debug: unit_carry.c
	$(CC) $(INCLUDE) -o carry_unit_debug $(CFLAGS) unit_carry.c -L../ -loctodebug

cll_unit_debug: unit_cll.c
	$(CC) $(INCLUDE) -o cll_unit_debug $(CFLAGS) unit_cll.c -L../ -loctodebug

loa_unit_debug: unit_loa.c
	$(CC) $(INCLUDE) -o loa_unit_debug $(CFLAGS) unit_loa.c -L../ -loctodebug

.PHONY: clean
clean:
	rm -f *.o
	rm -f *.o.debug
	rm -f *_test*
