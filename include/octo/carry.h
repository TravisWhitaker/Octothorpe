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

typedef struct
{
	uint64_t total_entries;
	uint64_t empty_buckets;
	uint64_t optimal_buckets;
	uint64_t colliding_buckets;
	uint8_t max_bucket_elements;
	long double load;
} octo_stat_carry_t;

octo_dict_carry_t *octo_carry_init(const size_t init_keylen, const size_t init_vallen, const uint64_t init_buckets, const uint8_t init_tolerance, const uint8_t *init_master_key);
void octo_carry_free(octo_dict_carry_t *target);
int octo_carry_insert(const void *key, const void *value, const octo_dict_carry_t *dict);
void *octo_carry_fetch(const void *key, const octo_dict_carry_t *dict);
int octo_carry_poke(const void *key, const octo_dict_carry_t *dict);
octo_dict_carry_t *octo_carry_rehash(octo_dict_carry_t *dict, const size_t new_keylen, const size_t new_vallen, const uint64_t new_buckets, const uint8_t new_tolerance, const uint8_t *new_master_key);
octo_dict_carry_t *octo_carry_rehash_safe(octo_dict_carry_t *dict, const size_t new_keylen, const size_t new_vallen, const uint64_t new_buckets, const uint8_t new_tolerance, const uint8_t *new_master_key);
octo_stat_carry_t *octo_carry_stats(octo_dict_carry_t *dict);
void octo_carry_stats_msg(octo_dict_carry_t *dict);

#endif
