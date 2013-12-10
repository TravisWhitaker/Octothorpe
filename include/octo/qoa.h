// libocto Copyright (C) Travis Whitaker 2013

#ifndef OCTO_QOA_H
#define OCTO_QOA_H

typedef struct
{
	size_t keylen;
	size_t vallen;
	size_t cellen;
	uint64_t bucket_count;
	uint8_t master_key[16];
	void *buckets;
} octo_dict_qoa_t;

typedef struct
{
	uint64_t total_entries;
	uint64_t empty_buckets;
	uint64_t optimal_buckets;
	uint64_t colliding_buckets;
	long double load;
} octo_stat_qoa_t;

octo_dict_qoa_t *octo_qoa_init(const size_t init_keylen, const size_t init_vallen, const uint64_t init_buckets, const uint8_t *init_master_key);
void octo_qoa_delete(octo_dict_qoa_t *target);
int octo_qoa_insert(const void *key, const void *value, const octo_dict_qoa_t *dict);
void *octo_qoa_fetch(const void *key, const octo_dict_qoa_t *dict);
int octo_qoa_poke(const void *key, const octo_dict_qoa_t *dict);
octo_dict_qoa_t *octo_qoa_rehash(octo_dict_qoa_t *dict, const size_t new_keylen, const size_t new_vallen, const uint64_t new_buckets, const uint8_t *new_master_key);
octo_dict_qoa_t *octo_qoa_rehash_safe(octo_dict_qoa_t *dict, const size_t new_keylen, const size_t new_vallen, const uint64_t new_buckets, const uint8_t *new_master_key);
octo_stat_qoa_t *octo_qoa_stats(octo_dict_qoa_t *dict);
void octo_qoa_stats_msg(octo_dict_qoa_t *dict);

#endif
