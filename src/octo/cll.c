// libocto Copyright (C) Travis Whitaker 2013

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <errno.h>

#include <octo/types.h>
#include <octo/debug.h>
#include <octo/hash.h>
#include <octo/cll.h>

// Allocate memory for and initialize a carry_dict:
octo_dict_cll_t *octo_carry_init(const size_t init_keylen, const size_t init_vallen, const uint64_t init_buckets, const uint8_t init_tolerance, const uint8_t *init_master_key)
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
	if(init_tolerance <= 0)
	{
		DEBUG_MSG("init_tolerance must not be zero");
		errno = EINVAL;
		return NULL;
	}

	// Allocate the new dict and populate the trivial fields:
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

	// Allocate the array of bucket pointers:
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
	 * carry_dicts slow but collision handling fast. Each bucket begins
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
	memcpy(output->master_key, init_master_key, 16);
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

// Insert a value into a carry_dict. Return 0 on success, 1 on malloc failure, 2 on unmanageable collision  :
int octo_carry_insert(const void *key, const void *value, const octo_dict_carry_t *dict)
{
	uint64_t hash;
	uint64_t index;

	octo_hash(key, dict->keylen, (unsigned char *)&hash, (const unsigned char *)dict->master_key);
	index = hash % dict->bucket_count;

	// If there's nothing in the bucket yet, insert the record:
	if(*((uint8_t *)*(dict->buckets + index)) == 0)
	{
		memcpy((uint8_t *)*(dict->buckets + index) + 2, key, dict->keylen);
		memcpy((uint8_t *)*(dict->buckets + index) + 2 + dict->keylen, value, dict->vallen);
		*((uint8_t *)*(dict->buckets + index)) += 1;
		return 0;
	}

	// Check to see if the key is already in the bucket:
	for(uint8_t i = 0; i < *((uint8_t *)*(dict->buckets + index)); i++)
	{
		if(memcmp(key, (uint8_t *)*(dict->buckets + index) + 2 + (i * dict->cellen), dict->keylen) == 0)
		{
			memcpy((uint8_t *)*(dict->buckets + index) + 2 + (i * dict->cellen) + dict->keylen, value, dict->vallen);
			return 0;
		}
	}

	// If the bucket is at capacity, expand it:
	if(*((uint8_t *)*(dict->buckets + index) + 1) == *((uint8_t *)*(dict->buckets + index)))
	{
		// ...but not if *((uint8_t *)*(dict->buckets + index) + 1) would overflow:
		if(*((uint8_t *)*(dict->buckets + index) + 1) == 255)
		{
			return 2;
		}
		void *bigger_bucket = realloc(*(dict->buckets + index),(2 * sizeof(uint8_t)) + (dict->cellen * (*((uint8_t *)*(dict->buckets + index) + 1) + 1)));
		if(bigger_bucket == NULL)
		{
			DEBUG_MSG("bucket realloc failed during insertion");
			errno = ENOMEM;
			return 1;
		}
		*(dict->buckets + index) = bigger_bucket;
		*((uint8_t *)*(dict->buckets + index) + 1) += 1;
	}

	// Insert the record at the end of the bucket:
	memcpy((uint8_t *)*(dict->buckets + index) + 2 + (dict->cellen * (*((uint8_t *)*(dict->buckets + index)))), key, dict->keylen);
	memcpy((uint8_t *)*(dict->buckets + index) + 2 + (dict->cellen * (*((uint8_t *)*(dict->buckets + index)))) + dict->keylen, value, dict->vallen);
	*((uint8_t *)*(dict->buckets + index)) += 1;
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

// Like octo_carry_fetch, but don't malloc/memcpy the value.
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

// Re-create the carry_dict with a new key length, value length(both will be truncated), number of buckets,
// tolerance value, and/or new master_key. Return pointer to new carry_dict on success, NULL on failure:
octo_dict_carry_t *octo_carry_rehash(octo_dict_carry_t *dict, const size_t new_keylen, const size_t new_vallen, const uint64_t new_buckets, const uint8_t new_tolerance, const uint8_t *new_master_key)
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
	if(new_tolerance <= 0)
	{
		DEBUG_MSG("init_tolerance must not be zero");
		errno = EINVAL;
		return NULL;
	}

	// Allocate the new dict and populate trivial fields:
	octo_dict_carry_t *output = malloc(sizeof(*output));
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
		octo_carry_delete(output);
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
	uint64_t hash;
	uint64_t index;
	for(uint64_t i = 0; i < dict->bucket_count; i++)
	{
		for(uint8_t j = 0; j < *((uint8_t *)*(dict->buckets + i)); j++)
		{
			memcpy(key_buffer, ((uint8_t *)*(dict->buckets + i) + 2 + (dict->cellen * j)), buffer_keylen);
			memcpy(val_buffer, ((uint8_t *)*(dict->buckets + i) + 2 + (dict->cellen * j) + dict->keylen), buffer_vallen);
			octo_hash((const unsigned char *)key_buffer, (unsigned long int)output->keylen, (unsigned char *)&hash, (const unsigned char *)output->master_key);
			index = hash % output->bucket_count;
			// If there isn't a bucket at this position yet, alloc and insert:
			if(*(output->buckets + index) == NULL)
			{
				*(output->buckets + index) = malloc((2 * sizeof(uint8_t)) + (output->cellen * new_tolerance));
				if(*(output->buckets + index) == NULL)
				{
					DEBUG_MSG("malloc failed while allocating new bucket");
					errno = ENOMEM;
					octo_carry_delete(output);
					return NULL;
				}
				*((uint8_t *)*(output->buckets + index)) = 1;
				*((uint8_t *)*(output->buckets + index) + 1) = new_tolerance;
				memcpy(((uint8_t *)*(output->buckets + index) + 2), key_buffer, output->keylen);
				memcpy(((uint8_t *)*(output->buckets + index) + 2 + output->keylen), val_buffer, output->vallen);
			}
			// Collision:
			else
			{
				bool found = false;
				// Search for the key(considering new key length) in the bucket:
				for(uint8_t k = 0; k < *((uint8_t *)*(output->buckets + index)); k++)
				{
					if(memcmp(key_buffer, ((uint8_t *)*(output->buckets + index) + 2 + (output->cellen * k)), output->keylen) == 0)
					{
						memcpy(((uint8_t *)*(output->buckets + index) + 2 + (output->cellen * k) + output->keylen), val_buffer, output->vallen);
						*((uint8_t *)*(output->buckets + index)) += 1;
						found = true;
						break;
					}
				}
				if(found == false)
				{
					// If the bucket is at capacity, expand it:
					if(*((uint8_t *)*(output->buckets + index)) == *((uint8_t *)*(output->buckets + index) + 1))
					{
						if(*((uint8_t *)*(output->buckets + index)) == 255)
						{
							DEBUG_MSG("unmanageable collision");
							octo_carry_delete(output);
							free(key_buffer);
							free(val_buffer);
							return NULL;
						}
						void *bigger_bucket = realloc(*(output->buckets + index), (2 * sizeof(uint8_t)) + (*((uint8_t *)*(output->buckets + index) + 1) + 1) * output->cellen);
						if(bigger_bucket == NULL)
						{
							DEBUG_MSG("realloc failed during rehash");
							errno = ENOMEM;
							octo_carry_delete(output);
							free(key_buffer);
							free(val_buffer);
							return NULL;
						}
						*(output->buckets + index) = bigger_bucket;
						*((uint8_t *)*(output->buckets + index) + 1) += 1;
					}
					// Insert at the end of the bucket:
					memcpy(((uint8_t *)*(output->buckets + index) + 2 + (output->cellen * (*((uint8_t *)*(output->buckets + index))))), key_buffer, output->keylen);
					memcpy(((uint8_t *)*(output->buckets + index) + 2 + (output->cellen * (*((uint8_t *)*(output->buckets + index)))) + output->keylen), val_buffer, output->vallen);
					*((uint8_t *)*(output->buckets + index)) += 1;
				}
			}
		}
		free(*(dict->buckets + i));
	}
	// At this point we're finished with the old dict, free it:
	free(dict->buckets);
	free(dict);
	free(key_buffer);
	free(val_buffer);
	// Now allocate buckets for the remaining NULL pointers:
	for(uint64_t i = 0; i < output->bucket_count; i++)
	{
		if(*(output->buckets + i) == NULL)
		{
			*(output->buckets + i) = malloc((2 * sizeof(uint8_t)) + (output->cellen * new_tolerance));
			if(*(output->buckets + i) == NULL)
			{
				DEBUG_MSG("malloc failed while finalizing new carry_dict; lazy rehash was used, data is unrecoverable");
				errno = ENOMEM;
				octo_carry_delete(output);
				return NULL;
			}
			*((uint8_t *)*(output->buckets + i)) = 0;
			*((uint8_t *)*(output->buckets + i) + 1) = new_tolerance;
		}
	}
	return output;
}

// Like octo_carry_rehash, but retain the original dict. It is up to the caller
// to free the old dict:
octo_dict_carry_t *octo_carry_rehash_safe(octo_dict_carry_t *dict, const size_t new_keylen, const size_t new_vallen, const uint64_t new_buckets, const uint8_t new_tolerance, const uint8_t *new_master_key)
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
	if(new_tolerance <= 0)
	{
		DEBUG_MSG("init_tolerance must not be zero");
		errno = EINVAL;
		return NULL;
	}

	// Allocate the new dict and populate trivial fields:
	octo_dict_carry_t *output = malloc(sizeof(*output));
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
		octo_carry_delete(output);
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
	uint64_t hash;
	uint64_t index;
	for(uint64_t i = 0; i < dict->bucket_count; i++)
	{
		for(uint8_t j = 0; j < *((uint8_t *)*(dict->buckets + i)); j++)
		{
			memcpy(key_buffer, ((uint8_t *)*(dict->buckets + i) + 2 + (dict->cellen * j)), buffer_keylen);
			memcpy(val_buffer, ((uint8_t *)*(dict->buckets + i) + 2 + (dict->cellen * j) + dict->keylen), buffer_vallen);
			octo_hash((const unsigned char *)key_buffer, (unsigned long int)output->keylen, (unsigned char *)&hash, (const unsigned char *)output->master_key);
			index = hash % output->bucket_count;
			// If there isn't a bucket at this position yet, alloc and insert:
			if(*(output->buckets + index) == NULL)
			{
				*(output->buckets + index) = malloc((2 * sizeof(uint8_t)) + (output->cellen * new_tolerance));
				if(*(output->buckets + index) == NULL)
				{
					DEBUG_MSG("malloc failed while allocating new bucket");
					errno = ENOMEM;
					octo_carry_delete(output);
					return NULL;
				}
				*((uint8_t *)*(output->buckets + index)) = 1;
				*((uint8_t *)*(output->buckets + index) + 1) = new_tolerance;
				memcpy(((uint8_t *)*(output->buckets + index) + 2), key_buffer, output->keylen);
				memcpy(((uint8_t *)*(output->buckets + index) + 2 + output->keylen), val_buffer, output->vallen);
			}
			// Collision:
			else
			{
				bool found = false;
				// Search for the key(considering new key length) in the bucket:
				for(uint8_t k = 0; k < *((uint8_t *)*(output->buckets + index)); k++)
				{
					if(memcmp(key_buffer, ((uint8_t *)*(output->buckets + index) + 2 + (output->cellen * k)), output->keylen) == 0)
					{
						memcpy(((uint8_t *)*(output->buckets + index) + 2 + (output->cellen * k) + output->keylen), val_buffer, output->vallen);
						*((uint8_t *)*(output->buckets + index)) += 1;
						found = true;
						break;
					}
				}
				if(found == false)
				{
					// If the bucket is at capacity, expand it:
					if(*((uint8_t *)*(output->buckets + index)) == *((uint8_t *)*(output->buckets + index) + 1))
					{
						if(*((uint8_t *)*(output->buckets + index)) == 255)
						{
							DEBUG_MSG("unmanageable collision");
							octo_carry_delete(output);
							free(key_buffer);
							free(val_buffer);
							return NULL;
						}
						void *bigger_bucket = realloc(*(output->buckets + index), (2 * sizeof(uint8_t)) + (*((uint8_t *)*(output->buckets + index) + 1) + 1) * output->cellen);
						if(bigger_bucket == NULL)
						{
							DEBUG_MSG("realloc failed during rehash");
							errno = ENOMEM;
							octo_carry_delete(output);
							free(key_buffer);
							free(val_buffer);
							return NULL;
						}
						*(output->buckets + index) = bigger_bucket;
						*((uint8_t *)*(output->buckets + index) + 1) += 1;
					}
					// Insert at the end of the bucket:
					memcpy(((uint8_t *)*(output->buckets + index) + 2 + (output->cellen * (*((uint8_t *)*(output->buckets + index))))), key_buffer, output->keylen);
					memcpy(((uint8_t *)*(output->buckets + index) + 2 + (output->cellen * (*((uint8_t *)*(output->buckets + index)))) + output->keylen), val_buffer, output->vallen);
					*((uint8_t *)*(output->buckets + index)) += 1;
				}
			}
		}
	}
	// Now allocate buckets for the remaining NULL pointers:
	for(uint64_t i = 0; i < output->bucket_count; i++)
	{
		if(*(output->buckets + i) == NULL)
		{
			*(output->buckets + i) = malloc((2 * sizeof(uint8_t)) + (output->cellen * new_tolerance));
			if(*(output->buckets + i) == NULL)
			{
				DEBUG_MSG("malloc failed while finalizing new carry_dict; lazy rehash was used, data is unrecoverable");
				errno = ENOMEM;
				octo_carry_delete(output);
				return NULL;
			}
			*((uint8_t *)*(output->buckets + i)) = 0;
			*((uint8_t *)*(output->buckets + i) + 1) = new_tolerance;
		}
	}
	return output;
}

// Populate and return a pointer to a octo_stat_carry_t on success, NULL on error:
octo_stat_carry_t *octo_carry_stats(octo_dict_carry_t *dict)
{
	octo_stat_carry_t *output = calloc(1, sizeof(octo_stat_carry_t));
	if(output == NULL)
	{
		DEBUG_MSG("malloc failed while allocating octo_stat_carry_t");
		errno = ENOMEM;
		return NULL;
	}
	for(uint64_t i = 0; i < dict->bucket_count; i++)
	{
		switch(*((uint8_t *)*(dict->buckets + i)))
		{
		case 0:
			output->empty_buckets++;
			break;
		case 1:
			output->optimal_buckets++;
			output->total_entries++;
			break;
		default:
			output->total_entries += *((uint8_t *)*(dict->buckets + i));
			output->colliding_buckets++;
			if(*((uint8_t *)*(dict->buckets + i)) > output->max_bucket_elements)
			{
				output->max_bucket_elements = *((uint8_t *)*(dict->buckets + i));
			}
			break;
		}
	}
	if(output->max_bucket_elements == 0)
	{
		output->max_bucket_elements = 1;
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

// Print out a summary of octo_stat_carry_t for debugging purposes:
void octo_carry_stats_msg(octo_dict_carry_t *dict)
{
	octo_stat_carry_t *output = calloc(1, sizeof(octo_stat_carry_t));
	if(output == NULL)
	{
		DEBUG_MSG("malloc failed while allocating octo_stat_carry_t");
		errno = ENOMEM;
		return;
	}
	for(uint64_t i = 0; i < dict->bucket_count; i++)
	{
		switch(*((uint8_t *)*(dict->buckets + i)))
		{
		case 0:
			output->empty_buckets++;
			break;
		case 1:
			output->optimal_buckets++;
			output->total_entries++;
			break;
		default:
			output->total_entries += *((uint8_t *)*(dict->buckets + i));
			output->colliding_buckets++;
			if(*((uint8_t *)*(dict->buckets + i)) > output->max_bucket_elements)
			{
				output->max_bucket_elements = *((uint8_t *)*(dict->buckets + i));
			}
			break;
		}
	}
	if(output->max_bucket_elements == 0)
	{
		output->max_bucket_elements = 1;
	}
	if((output->empty_buckets + output->optimal_buckets + output->colliding_buckets) != dict->bucket_count)
	{
		DEBUG_MSG("sum of bucket types not equal to bucket count");
		free(output);
		return;
	}
	output->load = ((long double)(output->total_entries))/((long double)(dict->bucket_count));
	printf("\n######## libocto octo_dict_carry_t statistics summary ########\n");
	printf("virtual address:%46llu\n", (unsigned long long)dict);
	printf("total entries:%48llu\n", (unsigned long long)output->total_entries);
	printf("empty buckets:%48llu\n", (unsigned long long)output->empty_buckets);
	printf("optimal buckets:%46llu\n", (unsigned long long)output->optimal_buckets);
	printf("colliding buckets:%44llu\n", (unsigned long long)output->colliding_buckets);
	printf("largest bucket:%47u\n", output->max_bucket_elements);
	printf("load factor:%50Lf\n", output->load);
	printf("##############################################################\n\n");
	free(output);
	return;
}
