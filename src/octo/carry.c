// libocto Copyright (C) Travis Whitaker 2013

#include <stdio.h>
#include <stdlib.h>

#include <errno.h>

#include <octo/debug.h>
#include <octo/carry.h>

// Allocate memory for and initialize a carry_dict:
octo_dict_carry_t *octo_carry_init(size_t init_keylen, size_t init_vallen, uint64_t init_buckets, uint8_t init_tolerance, uint8_t *init_master_key)
{
	octo_dict_carry_t *output = malloc(sizeof(*output));

	if(init_keylen <= 0)
	{
		DEBUG_MSG("key length must not be zero");
		errno = EINVAL;
		free(output);
		return NULL;
	}
	output->keylen = init_keylen;
	output->vallen = init_vallen;
	size_t cellen_tmp = init_keylen + init_vallen;
	if(cellen_tmp < init_keylen)
	{
		DEBUG_MSG("size_t overflow, keylen + vallen is too large");
		errno = EDOM;
		free(output);
		return NULL;
	}
	output->cellen = cellen_tmp;

	if(init_buckets <= 0)
	{
		DEBUG_MSG("init_buckets must not be zero");
		errno = EINVAL;
		free(output);
		return NULL;
	}
	void **buckets_tmp = malloc(sizeof(*buckets_tmp) * init_buckets);
	if(buckets_tmp == NULL)
	{
		DEBUG_MSG("unable to malloc for **buckets_tmp");
		errno = ENOMEM;
		free(output);
		return NULL;
	}
	if(init_tolerance <= 0)
	{
		DEBUG_MSG("init_tolerance must not be zero");
		errno = EINVAL;
		free(output);
		free(buckets_tmp);
		return NULL;
	}
	// This might be a terrible idea:
	for(uint64_t i = 0; i < init_buckets; i++)
	{
		*(buckets_tmp + i) = calloc(init_tolerance, sizeof(uint8_t) + output->cellen);
		if(*(buckets_tmp + i) == NULL)
		{
			DEBUG_MSG("calloc returned null while initializing bucket");
			errno = ENOMEM;
			free(output);
			free(buckets_tmp);
			return NULL;
		}
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
	free(target);
	return;
}
