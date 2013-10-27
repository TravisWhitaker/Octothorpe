// libocto Copyright (C) Travis Whitaker 2013

#ifndef OCTO_CARRY_H
#define OCTO_CARRY_H

typedef struct
{
	size_t keylen;
	size_t vallen;
	size_t cellen;
	uint64_t bucket_count;
	uint8_t master_key[16];
	void **buckets;
} octo_dict_carry_t;

octo_dict_carry_t *octo_carry_init(const size_t keylen, const size_t vallen, const uint64_t init_buckets, const uint8_t init_tolerance, const uint8_t *master_key);
void octo_carry_delete(octo_dict_carry_t *target);
int octo_carry_insert(const void *key, const void *value, const octo_dict_carry_t *dict);

#endif
