// libocto copyright (c) travis whitaker 2013-2014

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <errno.h>

#include <octo/types.h>
#include <octo/debug.h>
#include <octo/hash.h>
#include <octo/loa.h>

// Allocate memory for and initialize a loa_dict.
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
		DEBUG_MSG("unable to allocate buckets");
		errno = ENOMEM;
		free(output);
		return NULL;
	}
	output->bucket_count = init_buckets;
	output->buckets = buckets_tmp;
	memcpy(output->master_key, init_master_key, 16);
	return output;
}

// Delete a loa_dict.
void octo_loa_free(octo_dict_loa_t *target)
{
	free(target->buckets);
	free(target);
	return;
}

// Insert a value into a loa_dict. Return 0 on success, 1 on full bucket array.
int octo_loa_insert(const void *key, const void *value, const octo_dict_loa_t *dict)
{
	uint64_t hash;
	uint64_t index;

	octo_hash(key, dict->keylen, (uint8_t *)&hash, (const uint8_t *)dict->master_key);
	index = hash % dict->bucket_count;

	// If there's nothing in the bucket yet, insert the record:
	if(*((uint8_t *)dict->buckets + (index * (dict->cellen + 1))) == 0 || *((uint8_t *)dict->buckets + (index * (dict->cellen + 1))) == 0xbe)
	{
		*((uint8_t *)dict->buckets + (index * (dict->cellen + 1))) = 0xff;
		memcpy((uint8_t*)dict->buckets + (index * (dict->cellen + 1)) + 1, key, dict->keylen);
		memcpy((uint8_t *)dict->buckets + (index * (dict->cellen + 1)) + 1 + dict->keylen, value, dict->vallen);
		return 0;
	}
	// Are we updating a key's value?
	else if(memcmp(key, (uint8_t *)dict->buckets + (index * (dict->cellen + 1)) + 1, dict->keylen) == 0)
	{
		memcpy((uint8_t *)dict->buckets + (index * (dict->cellen + 1)) + 1 + dict->keylen, value, dict->vallen);
		return 0;
	}

	// Linearly probe the remaining addresses:
	uint64_t atmpt = 1;
	while(atmpt <= dict->bucket_count)
	{
		index = index + 1 < dict->bucket_count ? index + 1 : 0;
		// Is this bucket available?
		if(*((uint8_t *)dict->buckets + (index * (dict->cellen + 1))) == 0 || *((uint8_t *)dict->buckets + (index * (dict->cellen + 1))) == 0xbe)
		{
			*((uint8_t *)dict->buckets + (index * (dict->cellen + 1))) = 0xff;
			memcpy((uint8_t *)dict->buckets + (index * (dict->cellen + 1)) + 1, key, dict->keylen);
			memcpy((uint8_t *)dict->buckets + (index * (dict->cellen + 1)) + 1 + dict->keylen, value, dict->vallen);
			return 0;
		}
		// Did we find the key?
		else if(memcmp(key, (uint8_t *)dict->buckets + (index * (dict->cellen + 1)) + 1, dict->keylen) == 0)
		{
			memcpy((uint8_t *)dict->buckets + (index * (dict->cellen + 1)) + 1 + dict->keylen, value, dict->vallen);
			return 0;
		}
		atmpt++;
	}
	return 1;
}

// Fetch a value from a loa_dict. Return NULL on error, return a pointer to
// the loa_dict itself if the value is not found. The pointer referes to the
// literal location of the value; if you don't want that, use *fetch_safe.
void *octo_loa_fetch(const void *key, const octo_dict_loa_t *dict)
{
	uint64_t hash;
	uint64_t index;
	octo_hash(key, dict->keylen, (uint8_t *)&hash, (const uint8_t *)dict->master_key);
	index = hash % dict->bucket_count;

	// Is the bucket occupied?
	if(*((uint8_t *)dict->buckets + (index * (dict->cellen + 1))) != 0xff)
	{
		return (void *)dict;
	}
	// If so, did we find the key?
	if(memcmp(key, (uint8_t *)dict->buckets + (index * (dict->cellen + 1)) + 1, dict->keylen) == 0)
	{
		return (uint8_t *)dict->buckets + (index * (dict->cellen + 1)) + 1 + dict->keylen;
	}

	uint64_t atmpt = 1;
	while(atmpt <= dict->bucket_count)
	{
		index = index + 1 < dict->bucket_count ? index + 1 : 0;
		if(*((uint8_t *)dict->buckets + (index * (dict->cellen + 1))) == 0xbe)
		{
			atmpt++;
			continue;
		}
		if(*((uint8_t *)dict->buckets + (index * (dict->cellen + 1))) == 0)
		{
			return (void *)dict;
		}
		if(memcmp(key, (uint8_t *)dict->buckets + (index * (dict->cellen + 1)) + 1, dict->keylen) == 0)
		{
			return (uint8_t *)dict->buckets + (index * (dict->cellen + 1)) + 1 + dict->keylen;
		}
		atmpt++;
	}
	return (void *)dict;
}

// Fetch a value from a loa_dict. Return NULL on error, return a pointer to
// the loa_dict itself if the value is not found.
void *octo_loa_fetch_safe(const void *key, const octo_dict_loa_t *dict)
{
	uint64_t hash;
	uint64_t index;
	octo_hash(key, dict->keylen, (uint8_t *)&hash, (const uint8_t *)dict->master_key);
	index = hash % dict->bucket_count;

	// Is the bucket occupied?
	if(*((uint8_t *)dict->buckets + (index * (dict->cellen + 1))) != 0xff)
	{
		return (void *)dict;
	}
	// If so, did we find the key?
	if(memcmp(key, (uint8_t *)dict->buckets + (index * (dict->cellen + 1)) + 1, dict->keylen) == 0)
	{
		void *output = malloc(dict->vallen);
		if(output == NULL)
		{
			DEBUG_MSG("key found, but malloc failed");
			errno = ENOMEM;
			return NULL;
		}
		memcpy(output, (uint8_t *)dict->buckets + (index * (dict->cellen + 1)) + 1 + dict->keylen, dict->vallen);
		return output;
	}

	uint64_t atmpt = 1;
	while(atmpt <= dict->bucket_count)
	{
		index = index + 1 < dict->bucket_count ? index + 1 : 0;
		if(*((uint8_t *)dict->buckets + (index * (dict->cellen + 1))) == 0xbe)
		{
			atmpt++;
			continue;
		}
		if(*((uint8_t *)dict->buckets + (index * (dict->cellen + 1))) == 0)
		{
			return (void *)dict;
		}
		if(memcmp(key, (uint8_t *)dict->buckets + (index * (dict->cellen + 1)) + 1, dict->keylen) == 0)
		{
			void *output = malloc(dict->vallen);
			if(output == NULL)
			{
				DEBUG_MSG("key found, but malloc failed");
				errno = ENOMEM;
				return NULL;
			}
			memcpy(output, (uint8_t *)dict->buckets + (index * (dict->cellen + 1)) + 1 + dict->keylen, dict->vallen);
			return output;
		}
		atmpt++;
	}
	return (void *)dict;
}

// Like octo_loa_fetch, but don't malloc/memcpy the value.
// Return 1 if found, 0 if not.
int octo_loa_poke(const void *key, const octo_dict_loa_t *dict)
{
	uint64_t hash;
	uint64_t index;
	octo_hash(key, dict->keylen, (uint8_t *)&hash, (const uint8_t *)dict->master_key);
	index = hash % dict->bucket_count;

	// Is the bucket occupied?
	if(*((uint8_t *)dict->buckets + (index * (dict->cellen + 1))) != 0xff)
	{
		return 0;
	}
	// If so, did we find the key?
	if(memcmp(key, (uint8_t *)dict->buckets + (index * (dict->cellen + 1)) + 1, dict->keylen) == 0)
	{
		return 1;
	}

	uint64_t atmpt = 1;
	while(atmpt <= dict->bucket_count)
	{
		index = index + 1 < dict->bucket_count ? index + 1 : 0;
		if(*((uint8_t *)dict->buckets + (index * (dict->cellen + 1))) == 0xbe)
		{
			atmpt++;
			continue;
		}
		if(*((uint8_t *)dict->buckets + (index * (dict->cellen + 1))) == 0)
		{
			return 0;
		}
		if(memcmp(key, (uint8_t *)dict->buckets + (index * (dict->cellen + 1)) + 1, dict->keylen) == 0)
		{
			return 1;
		}
		atmpt++;
	}
	return 0;
}

// Delete the record with the given key. Return 1 on successful delete,
// 0 if the record isn't found.
int octo_loa_delete(const void *key, const octo_dict_loa_t *dict)
{
	uint64_t hash;
	uint64_t index;
	octo_hash(key, dict->keylen, (uint8_t *)&hash, (const uint8_t *)dict->master_key);
	index = hash % dict->bucket_count;

	// Is the bucket occupied?
	if(*((uint8_t *)dict->buckets + (index * (dict->cellen + 1))) != 0xff)
	{
		return 0;
	}
	// If so, did we find the key?
	if(memcmp(key, (uint8_t *)dict->buckets + (index * (dict->cellen + 1)) + 1, dict->keylen) == 0)
	{
		*((uint8_t *)dict->buckets + (index * (dict->cellen + 1))) = 0xbe;
		return 1;
	}

	uint64_t atmpt = 1;
	while(atmpt <= dict->bucket_count)
	{
		index = index + 1 < dict->bucket_count ? index + 1 : 0;
		if(*((uint8_t *)dict->buckets + (index * (dict->cellen + 1))) == 0xbe)
		{
			atmpt++;
			continue;
		}
		if(*((uint8_t *)dict->buckets + (index * (dict->cellen + 1))) == 0)
		{
			return 0;
		}
		if(memcmp(key, (uint8_t *)dict->buckets + (index * (dict->cellen + 1)) + 1, dict->keylen) == 0)
		{
			*((uint8_t *)dict->buckets + (index * (dict->cellen + 1))) = 0xbe;
			return 1;
		}
		atmpt++;
	}
	return 0;
}

// Re-create the loa_dict with a new key length, value length(both will be truncated), number of buckets,
// and/or new master_key. Return pointer to new loa_dict on success, NULL on failure.
octo_dict_loa_t *octo_loa_rehash(octo_dict_loa_t *dict, const size_t new_keylen, const size_t new_vallen, const uint64_t new_buckets, const uint8_t *new_master_key)
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
	octo_dict_loa_t *output = malloc(sizeof(*output));
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
		octo_loa_free(output);
		return NULL;
	}
	size_t buffer_keylen = dict->keylen < output->keylen ? dict->keylen : output->keylen;
	size_t buffer_vallen = dict->vallen < output->vallen ? dict->vallen : output->vallen;

	// Allocate the new array of buckets:
	void *buckets_tmp = calloc(new_buckets, output->cellen + 1);
	if(buckets_tmp == NULL)
	{
		DEBUG_MSG("unable to malloc for *buckets_tmp");
		errno = ENOMEM;
		free(output);
		return NULL;
	}
	output->buckets = buckets_tmp;

	for(uint64_t i = 0; i < dict->bucket_count; i++)
	{
		if(*((uint8_t *)dict->buckets + (i * (dict->cellen + 1))) == 0 || *((uint8_t *)dict->buckets + (i * (dict->cellen + 1))) == 0xbe)
		{
			continue;
		}
		memcpy(key_buffer, (uint8_t *)dict->buckets + (i * (dict->cellen + 1)) + 1, buffer_keylen);
		memcpy(val_buffer, (uint8_t *)dict->buckets + (i * (dict->cellen + 1)) + 1 + dict->keylen, buffer_vallen);
		if(octo_loa_insert(key_buffer, val_buffer, output) == 1)
		{
			DEBUG_MSG("octo_loa_insert failed, data may be recoverable");
			octo_loa_free(output);
			return NULL;
		}
	}
	// At this point we're finished with the old dict, free it:
	free(dict->buckets);
	free(dict);
	free(key_buffer);
	free(val_buffer);
	return output;
}

// Like octo_loa_rehash, but retain the original dict. It is up to the caller
// to free the old dict.
octo_dict_loa_t *octo_loa_rehash_safe(octo_dict_loa_t *dict, const size_t new_keylen, const size_t new_vallen, const uint64_t new_buckets, const uint8_t *new_master_key)
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
	octo_dict_loa_t *output = malloc(sizeof(*output));
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
		octo_loa_free(output);
		return NULL;
	}
	size_t buffer_keylen = dict->keylen < output->keylen ? dict->keylen : output->keylen;
	size_t buffer_vallen = dict->vallen < output->vallen ? dict->vallen : output->vallen;

	// Allocate the new array of buckets:
	void *buckets_tmp = calloc(new_buckets, output->cellen + 1);
	if(buckets_tmp == NULL)
	{
		DEBUG_MSG("unable to malloc for *buckets_tmp");
		errno = ENOMEM;
		free(output);
		return NULL;
	}
	output->buckets = buckets_tmp;

	for(uint64_t i = 0; i < dict->bucket_count; i++)
	{
		if(*((uint8_t *)dict->buckets + (i * (dict->cellen + 1))) == 0 || *((uint8_t *)dict->buckets + (i * (dict->cellen + 1))) == 0xbe)
		{
			continue;
		}
		memcpy(key_buffer, (uint8_t *)dict->buckets + (i * (dict->cellen + 1)) + 1, buffer_keylen);
		memcpy(val_buffer, (uint8_t *)dict->buckets + (i * (dict->cellen + 1)) + 1 + dict->keylen, buffer_vallen);
		if(octo_loa_insert(key_buffer, val_buffer, output) == 1)
		{
			DEBUG_MSG("octo_loa_insert failed, original dict in known-good state");
			octo_loa_free(output);
			return NULL;
		}
	}
	free(key_buffer);
	free(val_buffer);
	return output;
}

// Make a deep copy of a loa_dict. Return NULL on error, pointer to the new
// dict on success. Note that cloning loa_dicts is much faster than cloning
// other dict types.
octo_dict_loa_t *octo_loa_clone(octo_dict_loa_t *dict)
{
	// Allocate the new dict and populate trivial fields:
	octo_dict_loa_t *output = malloc(sizeof(*output));
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

	// Allocate the new array of buckets:
	void *buckets_tmp = calloc(output->bucket_count, output->cellen + 1);
	if(buckets_tmp == NULL)
	{
		DEBUG_MSG("unable to malloc for *buckets_tmp");
		errno = ENOMEM;
		free(output);
		return NULL;
	}
	output->buckets = buckets_tmp;
	// Nice and easy:
	memcpy(output->buckets, dict->buckets, output->bucket_count * (output->cellen * 1));
	return output;
}

// Populate and return a pointer to an octo_stat_loa_t on success, NULL on error.
octo_stat_loa_t *octo_loa_stats(octo_dict_loa_t *dict)
{
	octo_stat_loa_t *output = calloc(1, sizeof(*output));
	if(output == NULL)
	{
		DEBUG_MSG("malloc failed while allocating octo_stat_loa_t");
		errno = ENOMEM;
		return NULL;
	}
	uint64_t hash;
	for(uint64_t i = 0; i < dict->bucket_count; i++)
	{
		if(*((uint8_t *)dict->buckets + (i * (dict->cellen + 1))) == 0)
		{
			output->empty_buckets++;
			continue;
		}
		if(*((uint8_t *)dict->buckets + (i * (dict->cellen + 1))) == 0xbe)
		{
			output->garbage_buckets++;
			continue;
		}
		output->total_entries++;
		octo_hash((uint8_t const *)dict->buckets + (i * (dict->cellen + 1)) + 1, dict->keylen, (uint8_t *)&hash, (const uint8_t *)dict->master_key);
		if(i == hash % dict->bucket_count)
		{
			output->optimal_buckets++;
		}
		else
		{
			output->colliding_buckets++;
		}
	}
	if((output->empty_buckets + output->optimal_buckets + output->colliding_buckets) != dict->bucket_count)
	{
		DEBUG_MSG("sum of bucket types not equal to bucket count");
		free(output);
		return NULL;
	}
	output->load = ((long double)(output->total_entries))/((long double)(dict->bucket_count));
	return output;
}

// Print out a summary of octo_stat_loa_t for debugging purposes.
void octo_loa_stats_msg(octo_dict_loa_t *dict)
{
	octo_stat_loa_t *output = calloc(1, sizeof(*output));
	if(output == NULL)
	{
		DEBUG_MSG("malloc failed while allocating octo_stat_loa_t");
		errno = ENOMEM;
		return;
	}
	uint64_t hash;
	for(uint64_t i = 0; i < dict->bucket_count; i++)
	{
		if(*((uint8_t *)dict->buckets + (i * (dict->cellen + 1))) == 0)
		{
			output->empty_buckets++;
			continue;
		}
		if(*((uint8_t *)dict->buckets + (i * (dict->cellen + 1))) == 0xbe)
		{
			output->garbage_buckets++;
			continue;
		}
		output->total_entries++;
		octo_hash((uint8_t const *)dict->buckets + (i * (dict->cellen + 1)) + 1, dict->keylen, (uint8_t *)&hash, (const uint8_t *)dict->master_key);
		if(i == hash % dict->bucket_count)
		{
			output->optimal_buckets++;
		}
		else
		{
			output->colliding_buckets++;
		}
	}
	if((output->empty_buckets + output->optimal_buckets + output->colliding_buckets) != dict->bucket_count)
	{
		DEBUG_MSG("sum of bucket types not equal to bucket count");
		free(output);
		return;
	}
	output->load = ((long double)(output->total_entries))/((long double)(dict->bucket_count));
	printf("######## libocto octo_dict_loa_t statistics summary ########\n");
	printf("virtual address:%44llu\n", (unsigned long long)dict);
	printf("total entries:%46llu\n", (unsigned long long)output->total_entries);
	printf("empty buckets:%46llu\n", (unsigned long long)output->empty_buckets);
	printf("optimal buckets:%44llu\n", (unsigned long long)output->optimal_buckets);
	printf("colliding buckets:%42llu\n", (unsigned long long)output->colliding_buckets);
	printf("garbage buckets:%44llu\n", (unsigned long long)output->garbage_buckets);
	printf("load factor:%48Lf\n", output->load);
	printf("############################################################\n");
	free(output);
	return;
}
