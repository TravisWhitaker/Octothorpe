# libocto Copyright (C) Travis Whitaker 2013

# libocto is developed with clang:
CC=clang
CFLAGS= -Wall -Wextra -Werror -pedantic -O2 -pipe -march=native
DEBUG_CFLAGS= -Wall -Wextra -Werror -pedantic -O0 -g -pipe -DDEBUG_MSG
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
all: libocto.a

libocto.a: hash.o carry.o
	$(AR) $(ARFLAGS) libocto.a hash.o carry.o

hash.o: src/octo/hash.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $(FPIC) src/octo/hash.c

carry.o: src/octo/carry.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $(FPIC) src/octo/carry.c

.PHONY: test
test:
	make -C test

.PHONY: check
check: test

.PHONY: clean
clean:
	rm -f libocto.a
	rm -f libocto.so
	rm -f *.o
	make -C test clean
