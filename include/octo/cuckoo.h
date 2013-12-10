// libocto Copyright (C) Travis Whitaker 2013

#ifndef OCTO_CUCKOO_H
#define OCTO_CUCKOO_H

typedef struct
{
	size_t keylen;
	size_t vallen;
	size_t cellen;
	uint64_t bucket_count;
	uint8_t master_keys;
	uint8_t *key_block;
	uint8_t (*keygen);
	void *buckets;
} octo_dict_cuckoo_t;

typedef struct
{
	uint64_t total_entries;
	uint64_t empty_buckets;
	uint64_t optimal_buckets;
	uint64_t colliding_buckets;
	long double load;
} octo_stat_cuckoo_t;

octo_dict_cuckoo_t *octo_cuckoo_init(const size_t init_keylen, const size_t init_vallen, const uint64_t init_buckets, uint8_t (*init_keygen));
void octo_cuckoo_delete(octo_dict_cuckoo_t *target);
int octo_cuckoo_insert(const void *key, const void *value, const octo_dict_cuckoo_t *dict);
void *octo_cuckoo_fetch(const void *key, const octo_dict_cuckoo_t *dict);
int octo_cuckoo_poke(const void *key, const octo_dict_cuckoo_t *dict);
octo_dict_cuckoo_t *octo_cuckoo_rehash(octo_dict_cuckoo_t *dict, const size_t new_keylen, const size_t new_vallen, const uint64_t new_buckets, uint8_t (*new_keygen));
octo_dict_cuckoo_t *octo_cuckoo_rehash_safe(octo_dict_cuckoo_t *dict, const size_t new_keylen, const size_t new_vallen, const uint64_t new_buckets, uint8_t *(new_keygen));
octo_stat_cuckoo_t *octo_cuckoo_stats(octo_dict_cuckoo_t *dict);
void octo_cuckoo_stats_msg(octo_dict_cuckoo_t *dict);

#endif
