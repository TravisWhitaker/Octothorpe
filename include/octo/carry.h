// libocto Copyright (C) Travis Whitaker 2013

#ifndef OCTO_CARRY_H
#define OCTO_CARRY_H

#ifdef NO_STDINT
typedef uint8_t unsigned char;
typedef uint64_t unsigned long long int;
#else
#include <stdint.h>
#endif

typedef struct
{
	size_t keylen;
	size_t vallen;
	size_t cellen;
	uint64_t bucket_count;
	uint8_t master_key[16];
	void **buckets;
} octo_dict_carry_t;

octo_dict_carry_t *octo_carry_init(size_t keylen, size_t vallen, uint64_t init_buckets, uint8_t init_tolerance, uint8_t *master_key);
void octo_carry_delete(octo_dict_t *target);

#endif
