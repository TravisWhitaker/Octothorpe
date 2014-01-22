// libocto Copyright (C) Travis Whitaker 2013-2014

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <errno.h>

#include <octo/types.h>
#include <octo/debug.h>
#include <octo/hash.h>
#include <octo/cll.h>

// Allocate memory for and initialize a cll_dict.
octo_dict_cll_t *octo_cll_init(const size_t init_keylen, const size_t init_vallen, const uint64_t init_buckets, const uint8_t *init_master_key)
{
	// Make sure the arguments are valid:
	if(init_keylen <= 0)
	{
		DEBUG_MSG("key length must not be zero");
		errno = EINVAL;
		return NULL;
	}
	if(init_buckets <= 0)
	{
		DEBUG_MSG("init_buckets must not be zero");
		errno = EINVAL;
		return NULL;
	}

	// Allocate the new dict and populate the trivial fields:
	octo_dict_cll_t *output = malloc(sizeof(*output));
	output->keylen = init_keylen;
	output->vallen = init_vallen;
	const size_t cellen_tmp = init_keylen + init_vallen;
	if(cellen_tmp < init_keylen)
	{
		DEBUG_MSG("size_t overflow, keylen + vallen is too large");
		errno = EDOM;
		free(output);
		return NULL;
	}
	output->cellen = cellen_tmp;

	// Allocate the array of bucket pointers. Bucket slots are left
	// unalloc'd in cll_dicts, so use calloc here:
	void **buckets_tmp = calloc(init_buckets, sizeof(*buckets_tmp));
	if(buckets_tmp == NULL)
	{
		DEBUG_MSG("unable to allocate bucket pointer array");
		errno = ENOMEM;
		free(output);
		return NULL;
	}
	output->bucket_count = init_buckets;
	output->buckets = buckets_tmp;
	memcpy(output->master_key, init_master_key, 16);
	return output;
}

// Delete a cll_dict.
void octo_cll_free(octo_dict_cll_t *target)
{
	void *this = NULL;
	void *next = NULL;
	for(uint64_t i = 0; i < target->bucket_count; i++)
	{
		if(*(target->buckets + i) == NULL)
		{
			continue;
		}
		this = *(target->buckets + i);
		while(this != NULL)
		{
			next = *((void **)this);
			free(this);
			this = next;
		}
	}
	free(target->buckets);
	free(target);
	return;
}

// Insert a value into a cll_dict. Return 0 on success, 1 on malloc failure.
int octo_cll_insert(const void *key, const void *value, const octo_dict_cll_t *dict)
{
	uint64_t hash;
	uint64_t index;
	void *tmp;

	octo_hash(key, dict->keylen, (uint8_t *)&hash, (const uint8_t *)dict->master_key);
	index = hash % dict->bucket_count;

	// If there's nothing in the bucket yet, insert the record:
	if(*(dict->buckets + index) == NULL)
	{
		tmp = malloc(sizeof(void *) + dict->cellen);
		if(tmp == NULL)
		{
			DEBUG_MSG("unable to malloc new bucket");
			errno = ENOMEM;
			return 1;
		}
		*((void **)tmp) = NULL;
		memcpy((uint8_t *)tmp + sizeof(void *), key, dict->keylen);
		memcpy((uint8_t *)tmp + sizeof(void *) + dict->keylen, value, dict->vallen);
		*(dict->buckets + index) = tmp;
		return 0;
	}

	// Check to see if the key is already in the bucket:
	void *this = *(dict->buckets + index);
	void *next = NULL;
	void *old_head = this;
	while(this != NULL)
	{
		next = *((void **)this);
		if(memcmp(key, (uint8_t *)this + sizeof(void *), dict->keylen) == 0)
		{
			memcpy((uint8_t *)this + sizeof(void *) + dict->keylen, value, dict->vallen);
			return 0;
		}
		this = next;
	}

	// Nope, insert at the head of the chain:
	tmp = malloc(sizeof(void *) + dict->cellen);
	if(tmp == NULL)
	{
		DEBUG_MSG("unable to malloc new bucket");
		errno = ENOMEM;
		return 1;
	}
	*((void **)tmp) = old_head;
	memcpy((uint8_t *)tmp + sizeof(void *), key, dict->keylen);
	memcpy((uint8_t *)tmp + sizeof(void *) + dict->keylen, value, dict->vallen);
	*(dict->buckets + index) = tmp;
	return 0;
}

// Fetch a value from a cll_dict. Return NULL on error, return a pointer to
// the cll_dict itself if the value is not found. The pointer referes to the
// literal location of the record. If you don't want that, use *fetch_safe.
void *octo_cll_fetch(const void *key, const octo_dict_cll_t *dict)
{
	uint64_t hash;
	uint64_t index;
	octo_hash(key, dict->keylen, (uint8_t *)&hash, (const uint8_t *)dict->master_key);
	index = hash % dict->bucket_count;

	// If there's nothing in the bucket, the value isn't in the dict:
	if(*(dict->buckets + index) == NULL)
	{
		return (void *)dict;
	}

	void *this = *(dict->buckets + index);
	void *next = NULL;
	while(this != NULL)
	{
		next = *((void **)this);
		if(memcmp(key, (uint8_t *)this + sizeof(void *), dict->keylen) == 0)
		{
			return (uint8_t *)this + sizeof(void *) + dict->keylen;
		}
		this = next;
	}
	return (void *)dict;
}

// Fetch a value from a cll_dict. Return NULL on error, return a pointer to
// the cll_dict itself if the value is not found.
void *octo_cll_fetch_safe(const void *key, const octo_dict_cll_t *dict)
{
	uint64_t hash;
	uint64_t index;
	octo_hash(key, dict->keylen, (uint8_t *)&hash, (const uint8_t *)dict->master_key);
	index = hash % dict->bucket_count;

	// If there's nothing in the bucket, the value isn't in the dict:
	if(*(dict->buckets + index) == NULL)
	{
		return (void *)dict;
	}

	void *this = *(dict->buckets + index);
	void *next = NULL;
	while(this != NULL)
	{
		next = *((void **)this);
		if(memcmp(key, (uint8_t *)this + sizeof(void *), dict->keylen) == 0)
		{
			void *output = malloc(dict->vallen);
			if(output == NULL)
			{
				DEBUG_MSG("lookup successful but malloc failed");
				errno = ENOMEM;
				return NULL;
			}
			memcpy(output, (uint8_t *)this + sizeof(void *) + dict->keylen, dict->vallen);
			return output;
		}
		this = next;
	}
	return (void *)dict;
}

// Like octo_cll_fetch, but don't malloc/memcpy the value.
// Return 1 if found, 0 if not.
int octo_cll_poke(const void *key, const octo_dict_cll_t *dict)
{
	uint64_t hash;
	uint64_t index;
	octo_hash(key, dict->keylen, (uint8_t *)&hash, (const uint8_t *)dict->master_key);
	index = hash % dict->bucket_count;

	// If there's nothing in the bucket, the value isn't in the dict:
	if(*(dict->buckets + index) == NULL)
	{
		return 0;
	}

	void *this = *(dict->buckets + index);
	void *next = NULL;
	while(this != NULL)
	{
		next = *((void **)this);
		if(memcmp(key, (uint8_t *)this + sizeof(void *), dict->keylen) == 0)
		{
			return 1;
		}
		this = next;
	}
	return 0;
}

// Delete the record with the given key. Return 1 on successful delete,
// 0 if the record isn't found.
int octo_cll_delete(const void *key, const octo_dict_cll_t *dict)
{
	uint64_t hash;
	uint64_t index;
	octo_hash(key, dict->keylen, (uint8_t *)&hash, (const uint8_t *)dict->master_key);
	index = hash % dict->bucket_count;

	// If there's nothing in the bucket, the value isn't in the dict:
	if(*(dict->buckets + index) == NULL)
	{
		return 0;
	}

	void *this = *(dict->buckets + index);
	void *next = NULL;
	void *prev = NULL;
	while (this != NULL)
	{
		next = *((void **)this);
		if(memcmp(key, (uint8_t *)this + sizeof(void *), dict->keylen) == 0)
		{
			free(this);
			if(next == NULL)
			{
				if(prev == NULL)
				{
					*(dict->buckets + index) = NULL;
				}
				else
				{
					*((void **)prev) = NULL;
				}
			}
			else
			{
				if(prev == NULL)
				{
					*(dict->buckets + index) = next;
				}
				else
				{
					*((void **)prev) = next;
				}
			}
			return 1;
		}
		prev = this;
		this = next;
	}
	return 0;
}

// Re-create the cll_dict with a new key length, value length(both will be truncated), number of buckets,
// and/or new master_key. Return pointer to new cll_dict on success, NULL on failure.
octo_dict_cll_t *octo_cll_rehash(octo_dict_cll_t *dict, const size_t new_keylen, const size_t new_vallen, const uint64_t new_buckets, const uint8_t *new_master_key)
{
	// Make sure the arguments are valid:
	if(new_keylen <= 0)
	{
		DEBUG_MSG("key length must not be zero");
		errno = EINVAL;
		return NULL;
	}
	if(new_buckets <= 0)
	{
		DEBUG_MSG("init_buckets must not be zero");
		errno = EINVAL;
		return NULL;
	}

	// Allocate the new dict and populate trivial fields:
	octo_dict_cll_t *output = malloc(sizeof(*output));
	if(output == NULL)
	{
		DEBUG_MSG("malloc failed allocating *output");
		errno = ENOMEM;
		return NULL;
	}
	output->keylen = new_keylen;
	output->vallen = new_vallen;
	const size_t new_cellen = new_keylen + new_vallen;
	if(new_cellen < new_keylen)
	{
		DEBUG_MSG("size_t overflow, keylen + vallen is too large");
		errno = EDOM;
		free(output);
		return NULL;
	}
	output->cellen = new_cellen;
	output->bucket_count = new_buckets;
	memcpy(output->master_key, new_master_key, 16);
	// If the new keylen/vallen is longer than the old one, we need to read it from an initialized buffer:
	void *key_buffer = calloc(1, output->keylen);
	void *val_buffer = calloc(1, output->vallen);
	if(key_buffer == NULL || val_buffer == NULL)
	{
		DEBUG_MSG("malloc failed while allocating key/val buffer");
		errno = ENOMEM;
		octo_cll_free(output);
		return NULL;
	}
	size_t buffer_keylen = dict->keylen < output->keylen ? dict->keylen : output->keylen;
	size_t buffer_vallen = dict->vallen < output->vallen ? dict->vallen : output->vallen;

	// Allocate the new array of bucket pointers, initializing them to NULL:
	void **buckets_tmp = calloc(new_buckets, sizeof(*buckets_tmp));
	if(buckets_tmp == NULL)
	{
		DEBUG_MSG("unable to malloc for **buckets_tmp");
		errno = ENOMEM;
		free(output);
		return NULL;
	}
	output->buckets = buckets_tmp;
	void *this = NULL;
	void *next = NULL;
	// There's no pre-allocation to do, so simply find every key/val
	// in the dict and insert:
	for(uint64_t i = 0; i < dict->bucket_count; i++)
	{
		if(*(dict->buckets + i) == NULL)
		{
			continue;
		}
		this = *(dict->buckets + i);
		while(this != NULL)
		{
			next = *((void **)this);
			memcpy(key_buffer, (uint8_t *)this + sizeof(void *), buffer_keylen);
			memcpy(val_buffer, (uint8_t *)this + sizeof(void *) + dict->keylen, buffer_vallen);
			if(octo_cll_insert(key_buffer, val_buffer, output) == 1)
			{
				DEBUG_MSG("octo_cll_insert() failed during rehash, lazy rehash used, data is unrecoverable");
				return NULL;
			}
			free(this);
			this = next;
		}
	}
	// At this point we're finished with the old dict, free it:
	free(dict->buckets);
	free(dict);
	free(key_buffer);
	free(val_buffer);
	return output;
}

// Like octo_cll_rehash, but retain the original dict. It is up to the caller
// to free the old dict.
octo_dict_cll_t *octo_cll_rehash_safe(octo_dict_cll_t *dict, const size_t new_keylen, const size_t new_vallen, const uint64_t new_buckets, const uint8_t *new_master_key)
{
	// Make sure the arguments are valid:
	if(new_keylen <= 0)
	{
		DEBUG_MSG("key length must not be zero");
		errno = EINVAL;
		return NULL;
	}
	if(new_buckets <= 0)
	{
		DEBUG_MSG("init_buckets must not be zero");
		errno = EINVAL;
		return NULL;
	}

	// Allocate the new dict and populate trivial fields:
	octo_dict_cll_t *output = malloc(sizeof(*output));
	if(output == NULL)
	{
		DEBUG_MSG("malloc failed allocating *output");
		errno = ENOMEM;
		return NULL;
	}
	output->keylen = new_keylen;
	output->vallen = new_vallen;
	const size_t new_cellen = new_keylen + new_vallen;
	if(new_cellen < new_keylen)
	{
		DEBUG_MSG("size_t overflow, keylen + vallen is too large");
		errno = EDOM;
		free(output);
		return NULL;
	}
	output->cellen = new_cellen;
	output->bucket_count = new_buckets;
	memcpy(output->master_key, new_master_key, 16);
	// If the new keylen/vallen is longer than the old one, we need to read it from an initialized buffer:
	void *key_buffer = calloc(1, output->keylen);
	void *val_buffer = calloc(1, output->vallen);
	if(key_buffer == NULL || val_buffer == NULL)
	{
		DEBUG_MSG("malloc failed while allocating key/val buffer");
		errno = ENOMEM;
		octo_cll_free(output);
		return NULL;
	}
	size_t buffer_keylen = dict->keylen < output->keylen ? dict->keylen : output->keylen;
	size_t buffer_vallen = dict->vallen < output->vallen ? dict->vallen : output->vallen;

	// Allocate the new array of bucket pointers, initializing them to NULL:
	void **buckets_tmp = calloc(new_buckets, sizeof(*buckets_tmp));
	if(buckets_tmp == NULL)
	{
		DEBUG_MSG("unable to malloc for **buckets_tmp");
		errno = ENOMEM;
		free(output);
		return NULL;
	}
	output->buckets = buckets_tmp;
	void *this = NULL;
	void *next = NULL;
	// There's no pre-allocation to do, so simply find every key/val
	// in the dict and insert:
	for(uint64_t i = 0; i < dict->bucket_count; i++)
	{
		if(*(dict->buckets + i) == NULL)
		{
			continue;
		}
		this = *(dict->buckets + i);
		while(this != NULL)
		{
			next = *((void **)this);
			memcpy(key_buffer, (uint8_t *)this + sizeof(void *), buffer_keylen);
			memcpy(val_buffer, (uint8_t *)this + sizeof(void *) + dict->keylen, buffer_vallen);
			if(octo_cll_insert(key_buffer, val_buffer, output) == 1)
			{
				DEBUG_MSG("octo_cll_insert() failed during rehash, original cll_dict in known-good state");
				return NULL;
			}
			this = next;
		}
	}
	free(key_buffer);
	free(val_buffer);
	return output;
}

// Make a deep copy of a cll_dict. Return NULL on error, pointer to the new
// dict on success. Note that cloning cll_dicts is much slower than cloning
// other dict types.
octo_dict_cll_t *octo_cll_clone(octo_dict_cll_t *dict)
{
	// Allocate the new dict and populate trivial fields:
	octo_dict_cll_t *output = malloc(sizeof(*output));
	if(output == NULL)
	{
		DEBUG_MSG("malloc failed allocating *output");
		errno = ENOMEM;
		return NULL;
	}
	output->keylen = dict->keylen;
	output->vallen = dict->vallen;
	output->cellen = dict->cellen;
	output->bucket_count = dict->bucket_count;
	memcpy(output->master_key, dict->master_key, 16);

	// Allocate the new array of bucket pointers, initializing them to NULL:
	void **buckets_tmp = calloc(output->bucket_count, sizeof(*buckets_tmp));
	if(buckets_tmp == NULL)
	{
		DEBUG_MSG("unable to malloc for **buckets_tmp");
		errno = ENOMEM;
		free(output);
		return NULL;
	}
	output->buckets = buckets_tmp;
	void *src_this = NULL;
	void *src_next = NULL;
	void *new_this = NULL;
	void *new_next = NULL;
	void *tmp;
	for(uint64_t i = 0; i < dict->bucket_count; i++)
	{
		if(*(dict->buckets + i) == NULL)
		{
			continue;
		}
		src_this = *(dict->buckets + i);
		while(src_this != NULL)
		{
			src_next = *((void **)src_this);
			tmp = malloc(sizeof(void *) + output->cellen);
			*((void **)tmp) = NULL;
			// Is this the first node in this bucket?
			if(*(output->buckets + i) == NULL)
			{
				memcpy((uint8_t *)tmp + sizeof(void *), (uint8_t *)src_this + sizeof(void *), output->cellen);
				*(output->buckets + i) = tmp;
			}
			else
			{
				new_this = *(output->buckets + i);
				new_next = *((void **)new_this);
				while(new_next != NULL)
				{
					new_next = *((void **)new_this);
					new_this = new_next;
				}
				memcpy((uint8_t *)tmp + sizeof(void *), (uint8_t *)src_this + sizeof(void *), output->cellen);
				*((void **)new_this) = tmp;
			}
			src_this = src_next;
		}
	}
	return output;
}

// Populate and return a pointer to a octo_stat_cll_t on success, NULL on error.
octo_stat_cll_t *octo_cll_stats(octo_dict_cll_t *dict)
{
	octo_stat_cll_t *output = calloc(1, sizeof(*output));
	void *this;
	void *next;
	uint64_t current_chain_len;
	if(output == NULL)
	{
		DEBUG_MSG("malloc failed while allocating octo_stat_cll_t");
		errno = ENOMEM;
		return NULL;
	}
	for(uint64_t i = 0; i < dict->bucket_count; i++)
	{
		if(*(dict->buckets + i) == NULL)
		{
			output->null_buckets++;
			continue;
		}
		else if(*(void **)*(dict->buckets + i) == NULL)
		{
			output->optimal_buckets++;
			output->total_entries++;
			continue;
		}
		output->chained_buckets++;
		this = *(dict->buckets + i);
		current_chain_len = 0;
		while(this != NULL)
		{
			next = *((void **)this);
			current_chain_len++;
			output->total_entries++;
			this = next;
		}
		if(current_chain_len > output->max_chain_len)
		{
			output->max_chain_len = current_chain_len;
		}
	}
	if(output->max_chain_len == 0)
	{
		output->max_chain_len = 1;
	}
	if((output->null_buckets + output->optimal_buckets + output->chained_buckets) != dict->bucket_count)
	{
		DEBUG_MSG("sum of bucket types not equal to bucket count");
		free(output);
		return NULL;
	}
	output->load = ((long double)(output->total_entries))/((long double)(dict->bucket_count));
	return output;
}

// Print out a summary of octo_stat_cll_t for debugging purposes.
void octo_cll_stats_msg(octo_dict_cll_t *dict)
{
	octo_stat_cll_t *output = calloc(1, sizeof(*output));
	void *this;
	void *next;
	uint64_t current_chain_len;
	if(output == NULL)
	{
		DEBUG_MSG("malloc failed while allocating octo_stat_cll_t");
		errno = ENOMEM;
		return;
	}
	for(uint64_t i = 0; i < dict->bucket_count; i++)
	{
		if(*(dict->buckets + i) == NULL)
		{
			output->null_buckets++;
			continue;
		}
		else if(*((void **)*(dict->buckets + i)) == NULL)
		{
			output->optimal_buckets++;
			output->total_entries++;
			continue;
		}
		output->chained_buckets++;
		this = *(dict->buckets + i);
		current_chain_len = 0;
		while(this != NULL)
		{
			next = *((void **)this);
			current_chain_len++;
			output->total_entries++;
			this = next;
		}
		if(current_chain_len > output->max_chain_len)
		{
			output->max_chain_len = current_chain_len;
		}
	}
	if(output->max_chain_len == 0)
	{
		output->max_chain_len = 1;
	}
	if((output->null_buckets + output->optimal_buckets + output->chained_buckets) != dict->bucket_count)
	{
		DEBUG_MSG("sum of bucket types not equal to bucket count");
		free(output);
		return;
	}
	output->load = ((long double)(output->total_entries))/((long double)(dict->bucket_count));
	printf("######## libocto octo_dict_cll_t statistics summary ########\n");
	printf("virtual address:%44llu\n", (unsigned long long)dict);
	printf("total entries:%46llu\n", (unsigned long long)output->total_entries);
	printf("null buckets:%47llu\n", (unsigned long long)output->null_buckets);
	printf("optimal buckets:%44llu\n", (unsigned long long)output->optimal_buckets);
	printf("chained buckets:%44llu\n", (unsigned long long)output->chained_buckets);
	printf("longest chain:%46llu\n", (unsigned long long)output->max_chain_len);
	printf("load factor:%48Lf\n", output->load);
	printf("############################################################\n");
	free(output);
	return;
}
