// libocto Copyright (C) Travis Whitaker 2013

#ifndef OCTO_CLL_H
#define OCTO_CLL_H

typedef struct
{
	size_t keylen;
	size_t vallen;
	size_t cellen;
	uint64_t bucket_count;
	uint8_t master_key[16];
	void **buckets;
} octo_dict_cll_t;

typedef struct
{
	uint64_t total_entries;
	uint64_t null_buckets;
	uint64_t optimal_buckets;
	uint64_t chained_buckets;
	uint64_t max_chain_len;
	long double load;
} octo_stat_cll_t;

octo_dict_cll_t *octo_cll_init(const size_t init_keylen, const size_t init_vallen, const uint64_t init_buckets, const uint8_t *init_master_key);
void octo_cll_free(octo_dict_cll_t *target);
int octo_cll_insert(const void *key, const void *value, const octo_dict_cll_t *dict);
void *octo_cll_fetch(const void *key, const octo_dict_cll_t *dict);
int octo_cll_poke(const void *key, const octo_dict_cll_t *dict);
octo_dict_cll_t *octo_cll_rehash(octo_dict_cll_t *dict, const size_t new_keylen, const size_t new_vallen, const uint64_t new_buckets, const uint8_t *new_master_key);
octo_dict_cll_t *octo_cll_rehash_safe(octo_dict_cll_t *dict, const size_t new_keylen, const size_t new_vallen, const uint64_t new_buckets, const uint8_t *new_master_key);
octo_stat_cll_t *octo_cll_stats(octo_dict_cll_t *dict);
void octo_cll_stats_msg(octo_dict_cll_t *dict);

#endif
