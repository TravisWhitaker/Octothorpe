// libocto Copyright (C) Travis Whitaker 2013

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>

#include <octo/types.h>
#include <octo/debug.h>
#include <octo/hash.h>
#include <octo/carry.h>

// Allocate memory for and initialize a carry_dict:
octo_dict_carry_t *octo_carry_init(const size_t init_keylen, const size_t init_vallen, const uint64_t init_buckets, const uint8_t init_tolerance, const uint8_t *init_master_key)
{
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
	if(init_tolerance <= 0)
	{
		DEBUG_MSG("init_tolerance must not be zero");
		errno = EINVAL;
		return NULL;
	}

	octo_dict_carry_t *output = malloc(sizeof(*output));
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

	void **buckets_tmp = malloc(sizeof(*buckets_tmp) * init_buckets);
	if(buckets_tmp == NULL)
	{
		DEBUG_MSG("unable to malloc for **buckets_tmp");
		errno = ENOMEM;
		free(output);
		return NULL;
	}
	/*
	 * Each bucket is a small heap block. This makes creating and deleting
	 * carry_dicts slow and collision handling fast. Each bucket begins
	 * with two unsigned integers(8-bit ints by default). The first is the
	 * number of entries in the bucket, the next is the current number of
	 * entries that will fit in the bucket:
	 */
	for(uint64_t i = 0; i < init_buckets; i++)
	{
		*(buckets_tmp + i) = malloc((2 * sizeof(uint8_t)) + (cellen_tmp * init_tolerance));
		if(*(buckets_tmp + i) == NULL)
		{
			DEBUG_MSG("malloc returned null while initializing bucket");
			errno = ENOMEM;
			for(uint64_t j = 0; j < i; j++)
			{
				free(*(buckets_tmp + j));
			}
			free(buckets_tmp);
			free(output);
			return NULL;
		}
		*((uint8_t *)*(buckets_tmp + i)) = 0;
		*((uint8_t *)*(buckets_tmp + i) + 1) = init_tolerance;
	}
	output->bucket_count = init_buckets;
	output->buckets = buckets_tmp;
	for(unsigned int i = 0; i < 16; i++)
	{
		output->master_key[i] = init_master_key[i];
	}
	return output;
}

// Delete a carry_dict:
void octo_carry_delete(octo_dict_carry_t *target)
{
	for(uint64_t i = 0; i < target->bucket_count; i++)
	{
		free(*(target->buckets + i));
	}
	free(target->buckets);
	free(target);
	return;
}

// Insert a value into a carry_dict. Return 0 on success:
int octo_carry_insert(const void *key, const void *value, const octo_dict_carry_t *dict)
{
	uint64_t hash;
	uint64_t index;
	uint8_t bucket_occupied;
	uint8_t bucket_available;

	octo_hash(key, dict->keylen, (unsigned char *)&hash, (const unsigned char *)dict->master_key);
	index = hash % dict->bucket_count;
	bucket_occupied = *((uint8_t *)*(dict->buckets + index));
	bucket_available = *((uint8_t *)*(dict->buckets + index) + 1);

	// If there's nothing in the bucket yet, insert the record:
	if(bucket_occupied == 0)
	{
		memcpy((uint8_t *)*(dict->buckets + index) + 2, key, dict->keylen);
		memcpy((uint8_t *)*(dict->buckets + index) + 2 + dict->keylen, value, dict->vallen);
		bucket_occupied++;
		memcpy(((uint8_t *)*(dict->buckets + index)), &bucket_occupied, sizeof(uint8_t));
		return 0;
	}

	// Check to see if the key is already in the bucket:
	for(uint8_t i = 0; i < bucket_occupied; i++)
	{
		if(memcmp(key, (uint8_t *)*(dict->buckets + index) + 2 + (i * dict->cellen), dict->keylen) == 0)
		{
			memcpy((uint8_t *)*(dict->buckets + index) + 2 + (i * dict->cellen) + dict->keylen, value, dict->vallen);
			return 0;
		}
	}

	// If the bucket is at capacity, expand it:
	if(bucket_available == bucket_occupied)
	{
		void *bigger_bucket = realloc(*(dict->buckets + index),(2 * sizeof(uint8_t)) + (dict->cellen * (bucket_available + 1)));
		if(bigger_bucket == NULL)
		{
			DEBUG_MSG("bucket realloc failed during insertion");
			errno = ENOMEM;
			return 1;
		}
		*(dict->buckets + index) = bigger_bucket;
		bucket_available++;
		memcpy(((uint8_t *)*(dict->buckets + index) + 1), &bucket_available, sizeof(uint8_t));
	}

	// Insert the record at the end of the bucket:
	memcpy((uint8_t *)*(dict->buckets + index) + 2 + (dict->cellen * bucket_occupied), key, dict->keylen);
	memcpy((uint8_t *)*(dict->buckets + index) + 2 + (dict->cellen * bucket_occupied) + dict->keylen, value, dict->vallen);
	bucket_occupied++;
	memcpy(((uint8_t *)*(dict->buckets + index)), &bucket_occupied, sizeof(uint8_t));
	return 0;
}

// Fetch a value from a carry_dict. Return NULL on error, return a pointer to
// the carry_dict itself if the value is not found:
void *octo_carry_fetch(const void *key, const octo_dict_carry_t *dict)
{
	uint64_t hash;
	uint64_t index;
	octo_hash(key, dict->keylen, (unsigned char *)&hash, (const unsigned char *)dict->master_key);
	index = hash % dict->bucket_count;
	// If there's nothing in the bucket, the value isn't in the dict:
	if(*((uint8_t *)*(dict->buckets + index)) == 0)
	{
		return (void *)dict;
	}
	for(uint8_t i = 0; i < *((uint8_t *)*(dict->buckets + index)); i++)
	{
		if(memcmp(key, (uint8_t *)*(dict->buckets + index) + 2 + (dict->cellen * i), dict->keylen) == 0)
		{
			void *output = malloc(dict->vallen);
			if(output == NULL)
			{
				DEBUG_MSG("lookup successful but malloc failed");
				errno = ENOMEM;
				return NULL;
			}
			memcpy(output, (uint8_t *)*(dict->buckets + index) + 2 + (dict->cellen * i) + dict->keylen, dict->vallen);
			return output;
		}
	}
	return (void *)dict;
}

// Like octo_carry_fetch, but only test for the value.
// Return 1 if found, 0 if not:
int octo_carry_poke(const void *key, const octo_dict_carry_t *dict)
{
	uint64_t hash;
	uint64_t index;
	octo_hash(key, dict->keylen, (unsigned char *)&hash, (const unsigned char *)dict->master_key);
	index = hash % dict->bucket_count;
	// If there's nothing in the bucket, the value isn't in the dict:
	if(*((uint8_t *)*(dict->buckets + index)) == 0)
	{
		return 0;
	}
	for(uint8_t i = 0; i < *((uint8_t *)*(dict->buckets + index)); i++)
	{
		if(memcmp(key, (uint8_t *)*(dict->buckets + index) + 2 + (dict->cellen * i), dict->keylen) == 0)
		{
			return 1;
		}
	}
	return 0;
}
