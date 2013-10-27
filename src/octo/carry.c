// libocto Copyright (C) Travis Whitaker 2013

#include <stdio.h>
#include <stdlib.h>

#include <errno.h>

#include <octo/types.h>
#include <octo/debug.h>
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
