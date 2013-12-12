// libocto Copyright (C) Travis Whitaker 2013

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <errno.h>

#include <octo/types.h>
#include <octo/debug.h>
#include <octo/hash.h>
#include <octo/loa.h>

// Allocate memory for and initialize a loa_dict:
octo_dict_loa_t *octo_loa_init(const size_t init_keylen, const size_t init_vallen, const uint64_t init_buckets, const uint8_t *init_master_key)
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
	octo_dict_loa_t *output = malloc(sizeof(*output));
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

	// Allocate the array of buckets:
	void *buckets_tmp = calloc(init_buckets, output->cellen + 1);
	if(buckets_tmp == NULL)
	{
		DEBUG_MSG("unable to malloc for **buckets_tmp");
		errno = ENOMEM;
		free(output);
		return NULL;
	}
	output->bucket_count = init_buckets;
	output->buckets = buckets_tmp;
	memcpy(output->master_key, init_master_key, 16);
	return output;
}

// Delete a loa_dict:
void octo_loa_delete(octo_dict_loa_t *target)
{
	free(target->buckets);
	free(target);
	return;
}

// Insert a value into a loa_dict. Return 0 on success, 1 on full bucket array:
int octo_loa_insert(const void *key, const void *value, const octo_dict_loa_t *dict)
{
	uint64_t hash;
	uint64_t index;

	octo_hash(key, dict->keylen, (unsigned char *)&hash, (const unsigned char *)dict->master_key);
	index = hash % dict->bucket_count;

	// If there's nothing in the bucket yet, insert the record:
	if((char)*(dict->buckets + index) == 0)
	{
		(char)*(dict->buckets + index) = 0xff;
		memcpy(dict->buckets + index + 1, key, dict->keylen);
		memcpy(dict->buckets + index + 1 + dict->keylen, value, dict->vallen);
		return 0;
	}
	// Are we updating a key's value?
	else if(memcmp(key, dict->buckets + index + 1, dict->keylen) == 0)
	{
		memcpy(dict->buckets + index + 1 + dict->keylen, value, dict->vallen);
		return 0;
	}

	// Linearly probe the remaining addresses:
	uint64_t atmpt = 1;
	while(atmpt < dict->bucket_count)
	{
		index = index < (dict->buckets + dict->bucket_count) ? index + 1 : 0;
		// Is this bucket available?
		if((char)*(dict->buckets + index) == 0)
		{
			(char)*(dict->buckets + index) = 0xff;
			memcpy(dict->buckets + index + 1, key, dict->keylen);
			memcpy(dict->buckets + index + 1 + dict->keylen, value, dict->vallen);
			return 0;
		}
		// Did we find the key?
		else if(memcmp(key, dict->buckets + index + 1, dict->keylen) == 0)
		{
			memcpy(dict->buckets + index + 1 + dict->keylen, value, dict->vallen);
			return 0;
		}
		atmpt++;
	}
	return 1;
}

// Fetch a value from a loa_dict. Return NULL on error, return a pointer to
// the loa_dict itself if the value is not found:
void *octo_loa_fetch(const void *key, const octo_dict_loa_t *dict)
{
	uint64_t hash;
	uint64_t index;
	octo_hash(key, dict->keylen, (unsigned char *)&hash, (const unsigned char *)dict->master_key);
	index = hash % dict->bucket_count;

	//Is the bucket occupied? If so, did we find the key?
	if((char)*(dict->buckets + index) == 0xff && memcmp(key, dict->buckets + index + 1, key, dict->keylen) == 0)
	{
		void *output = malloc(sizeof(dict->vallen));
		if(output == NULL)
		{
			DEBUG_MSG("key found, but malloc failed")
			errno = ENOMEM;
			return NULL;
		}
		memcpy(output, dict->buckets + index + 1 + dict->keylen, dict->vallen);
		return output;
	}
	
	uint64_t atmpt = 1;
	while(atmpt < dict->bucket_count)
	{
		index = index < (dict->buckets + dict->bucket_count) ? index + 1 : 0;
		if((char)*(dict->buckets + index) == 0)
		{
			return (void *)dict;
		}
		if(memcmp(key, dict->buckets + index + 1, key, dict->keylen) == 0)
		{
			void *output = malloc(sizeof(dict->vallen));
			if(output == NULL)
			{
				DEBUG_MSG("key found, but malloc failed");
				errno = ENOMEM;
				return NULL;
			}
			memcpy(output, dict->buckets + index + 1 + dict->keylen, dict->vallen);
			return output;
		}
		atmpt++;
	}
	return (void *)dict;
}

// Like octo_cll_fetch, but don't malloc/memcpy the value.
// Return 1 if found, 0 if not:
int octo_cll_poke(const void *key, const octo_dict_cll_t *dict)
{
	uint64_t hash;
	uint64_t index;
	octo_hash(key, dict->keylen, (unsigned char *)&hash, (const unsigned char *)dict->master_key);
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
		if(memcmp(key, (char *)this + sizeof(void *), dict->keylen) == 0)
		{
			return 1;
		}
		this = next;
	}
	return 0;
}

// Re-create the cll_dict with a new key length, value length(both will be truncated), number of buckets,
// and/or new master_key. Return pointer to new cll_dict on success, NULL on failure:
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
		octo_cll_delete(output);
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
			memcpy(key_buffer, (char *)this + sizeof(void *), buffer_keylen);
			memcpy(val_buffer, (char *)this + sizeof(void *) + dict->keylen, buffer_vallen);
			octo_cll_insert(key_buffer, val_buffer, output);
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
// to free the old dict:
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
		octo_cll_delete(output);
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
			memcpy(key_buffer, (char *)this + sizeof(void *), buffer_keylen);
			memcpy(val_buffer, (char *)this + sizeof(void *) + dict->keylen, buffer_vallen);
			octo_cll_insert(key_buffer, val_buffer, output);
			this = next;
		}
	}
	free(key_buffer);
	free(val_buffer);
	return output;
}

// Populate and return a pointer to a octo_stat_cll_t on success, NULL on error:
octo_stat_cll_t *octo_cll_stats(octo_dict_cll_t *dict)
{
	octo_stat_cll_t *output = calloc(1, sizeof(octo_stat_cll_t));
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

// Print out a summary of octo_stat_cll_t for debugging purposes:
void octo_cll_stats_msg(octo_dict_cll_t *dict)
{
	octo_stat_cll_t *output = calloc(1, sizeof(octo_stat_cll_t));
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
	printf("\n######## libocto octo_dict_cll_t statistics summary ########\n");
	printf("virtual address:%44llu\n", (unsigned long long)dict);
	printf("total entries:%46llu\n", (unsigned long long)output->total_entries);
	printf("null buckets:%47llu\n", (unsigned long long)output->null_buckets);
	printf("optimal buckets:%44llu\n", (unsigned long long)output->optimal_buckets);
	printf("chained buckets:%44llu\n", (unsigned long long)output->chained_buckets);
	printf("longest chain:%46llu\n", (unsigned long long)output->max_chain_len);
	printf("load factor:%48Lf\n", output->load);
	printf("############################################################\n\n");
	free(output);
	return;
}
