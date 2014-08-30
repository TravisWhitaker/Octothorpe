# libocto Copyright (C) Travis Whitaker 2013-2014

# libocto is developed with clang:
CC=clang
CFLAGS= -Wall -Wextra -Werror -pedantic -O2 -pipe -march=native
DEBUG_CFLAGS= -Wall -Wextra -Werror -pedantic -O0 -g -ggdb -pipe -DDEBUG_MSG_ENABLE
INCLUDE= -I./include

# You make need to change this to '-fpic' if you're using a strange
# architecture like ancient SPARC or MIPS:
FPIC= -fPIC

# Archiver for building the static library:
AR=ar
ARFLAGS=rvs

# Defualt values for user-supplied compile time directives:
DEBUG_MSG=
HEADER_WIDTH=
NO_STDINT=

# Enable debugging messages outside of the 'debug' target:
ifeq ($(DEBUG_MSG),y)
	CFLAGS += -DDEBUG_MSG_ENABLE
endif

# Manually disable the use of stdint.h if you lack the feature test macros:
ifeq ($(NO_STDINT),y)
	CFLAGS += -DNO_STDINT
endif

# Choose an alternate width for the headers in the dict types that use them.
# Note that this will screw with struct alignment and waste lots of space:
ifeq ($(HEADER_WIDTH),16)
	CFLAGS += -DHEADER_WIDTH=16
else
ifeq ($(HEADER_WIDTH),32)
	CFLAGS += -DHEADER_WIDTH=32
else
# You're evil.
ifeq ($(HEADER_WIDTH),64)
	CFLAGS += -DHEADER_WIDTH=64
endif
endif
endif

.PHONY: all
all: libocto.a test

libocto.a: hash.o carry.o cll.o loa.o keygen.o
	$(AR) $(ARFLAGS) libocto.a hash.o carry.o cll.o loa.o keygen.o

hash.o: src/octo/hash.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $(FPIC) src/octo/hash.c

carry.o: src/octo/carry.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $(FPIC) src/octo/carry.c

cll.o: src/octo/cll.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $(FPIC) src/octo/cll.c

loa.o: src/octo/loa.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $(FPIC) src/octo/loa.c

keygen.o: src/octo/keygen.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $(FPIC) src/octo/keygen.c

.PHONY: test
test: libocto.a
	make -C test

.PHONY: test.debug
test.debug: liboctodebug.a
	make -C test debug

.PHONY: debug
debug: liboctodebug.a test.debug

liboctodebug.a: hash.o.debug carry.o.debug cll.o.debug loa.o.debug keygen.o.debug
	$(AR) $(ARFLAGS) liboctodebug.a hash.o.debug carry.o.debug cll.o.debug loa.o.debug keygen.o.debug

hash.o.debug: src/octo/hash.c
	$(CC) -c $(DEBUG_CFLAGS) $(INCLUDE) $(FPIC) src/octo/hash.c -o hash.o.debug

carry.o.debug: src/octo/carry.c
	$(CC) -c $(DEBUG_CFLAGS) $(INCLUDE) $(FPIC) src/octo/carry.c -o carry.o.debug

cll.o.debug: src/octo/cll.c
	$(CC) -c $(DEBUG_CFLAGS) $(INCLUDE) $(FPIC) src/octo/cll.c -o cll.o.debug

loa.o.debug: src/octo/loa.c
	$(CC) -c $(DEBUG_CFLAGS) $(INCLUDE) $(FPIC) src/octo/loa.c -o loa.o.debug

keygen.o.debug: src/octo/keygen.c
	$(CC) -c $(DEBUG_CFLAGS) $(INCLUDE) $(FPIC) src/octo/keygen.c -o keygen.o.debug

.PHONY: check
check: test

.PHONY: clean
clean:
	rm -f libocto.a
	rm -f libocto.so
	rm -f liboctodebug.a
	rm -f *.o
	rm -f *.o.debug
	make -C test clean
