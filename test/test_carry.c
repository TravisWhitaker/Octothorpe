// libocto Copyright (C) Travis Whitaker 2013

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>

#include <octo/types.h>
#include <octo/carry.h>

int main()
{
	uint8_t init_master_key[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 'a', 'b', 'c', 'd', 'e', 'f'};
	printf("test_carry: Creating test carry_dict...\n");
	octo_dict_carry_t *test_carry = octo_carry_init(8, 64, 10000000, 2, init_master_key);
	if(test_carry == NULL)
	{
		printf("test_carry: FAILED: octo_carry_init returned NULL\n");
		return 1;
	}
	for(uint64_t i = 0; i < test_carry->bucket_count; i++)
	{
		if(*((uint8_t *)(test_carry->buckets[i])) != 0)
		{
			printf("test_carry: FAILED: bucket %ld has incorrect entry count\nexpected %d, found %d\n", i, 0, *((uint8_t *)(test_carry->buckets[i])));
			return 1;
		}
		if(*((uint8_t *)(test_carry->buckets[i]) + 1) != 2)
		{
			printf("test_carry: FAILED: bucket %ld has incorrect tolerance value\bexpected %d, found %d\n", i, 2, *((uint8_t *)(test_carry->buckets[i]) + 1));
			return 1;
		}
	}
	printf("test_carry: Doing test insert...\n");
	if(octo_carry_insert("abcdefg\0", "123456781234567812345678123456781234567812345678123456781234567\0", (const octo_dict_carry_t *)test_carry) > 0)
	{
		printf("test_carry: FAILED: octo_carry_insert returned error code\n");
		return 1;
	}
	printf("test_carry: Poking inserted record...\n");
	if(!(octo_carry_poke("abcdefg\0", (const octo_dict_carry_t *)test_carry)))
	{
		printf("test_carry: FAILED: octo_carry_poke couldn't find test value\n");
		return 1;
	}
	printf("test_carry: Poking non-existent record...\n");
	if(octo_carry_poke("zfeuids\n", (const octo_dict_carry_t *)test_carry))
	{
		printf("test_carry: FAILED: octo_carry_poke found non-existent key\n");
		return 1;
	}
	printf("test_carry: Fetching inserted record...\n");
	void *output = octo_carry_fetch("abcdefg\0", (const octo_dict_carry_t *)test_carry);
	if(output == NULL)
	{
		printf("test_carry: FAILED: octo_carry_fetch returned NULL\n");
		return 1;
	}
	if(output == (void *)test_carry)
	{
		printf("test_carry: FAILED: octo_carry_fetch couldn't find test value\n");
		return 1;
	}
	printf("test_carry: Checking for correct value...\n");
	if(memcmp("123456781234567812345678123456781234567812345678123456781234567\0", output, 64) != 0)
	{
		printf("test_carry: FAILED: octo_carry_fetch returned pointer to incorrect value\n");
		return 1;
	}
	free(output);
	printf("test_carry: Looking up non-existent key...\n");
	output = octo_carry_fetch("zxcvbde\0", (const octo_dict_carry_t *)test_carry);
	if(output == NULL)
	{
		printf("test_carry: FAILED: octo_carry_fetch returned NULL\n");
		return 1;
	}
	if(output != (void *)test_carry)
	{
		printf("test_carry: FAILED: octo_carry_fetch reported hit for non-existent key\n");
		return 1;
	}
	printf("test_carry: Rehashing dict...\n");
//	uint8_t new_master_key[16] = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 'g', 'h', 'i', 'j', 'k', 'l'};
	test_carry = octo_carry_rehash(test_carry, test_carry->keylen, test_carry->vallen, test_carry->bucket_count, 2, test_carry->master_key);
	printf("test_carry: Poking inserted record...\n");
	if(!(octo_carry_poke("abcdefg\0", (const octo_dict_carry_t *)test_carry)))
	{
		printf("test_carry: FAILED: octo_carry_poke couldn't find test value\n");
		return 1;
	}
	printf("test_carry: Poking non-existent record...\n");
	if(octo_carry_poke("zfeuids\n", (const octo_dict_carry_t *)test_carry))
	{
		printf("test_carry: FAILED: octo_carry_poke found non-existent key\n");
		return 1;
	}
	printf("test_carry: Fetching inserted record...\n");
	output = octo_carry_fetch("abcdefg\0", (const octo_dict_carry_t *)test_carry);
	if(output == NULL)
	{
		printf("test_carry: FAILED: octo_carry_fetch returned NULL\n");
		return 1;
	}
	if(output == (void *)test_carry)
	{
		printf("test_carry: FAILED: octo_carry_fetch couldn't find test value\n");
		return 1;
	}
	printf("test_carry: Checking for correct value...\n");
	if(memcmp("123456781234567812345678123456781234567812345678123456781234567\0", output, 64) != 0)
	{
		printf("test_carry: FAILED: octo_carry_fetch returned pointer to incorrect value\n");
		return 1;
	}
	free(output);
	printf("test_carry: Looking up non-existent key...\n");
	output = octo_carry_fetch("zxcvbde\n", (const octo_dict_carry_t *)test_carry);
	if(output == NULL)
	{
		printf("test_carry: FAILED: octo_carry_fetch returned NULL\n");
		return 1;
	}
	if(output != (void *)test_carry)
	{
		printf("test_carry: FAILED: octo_carry_fetch reported hit for non-existent key\n");
		return 1;
	}
	if(test_carry == NULL)
	{
		printf("test_carry: FAILED: octo_carry_rehash returned null\n");
		return 1;
	}
	printf("test_carry: Deleting carry_dict...\n");
	octo_carry_delete(test_carry);
	printf("test_carry: SUCCESS!\n");
	return 0;
}
