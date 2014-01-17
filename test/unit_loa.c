// libocto Copyright (C) Travis Whitaker 2013

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>

#include <octo/types.h>
#include <octo/keygen.h>
#include <octo/loa.h>

char key1[8] = "abcdefg\0";
char key2[8] = "bcdefgh\0";
char key3[8] = "cdefghi\0";
char val1[64] = "123456781234567812345678123456781234567812345678123456781234567\0";
char val2[64] = "234567892345678923456789234567892345678923456789234567892345678\0";
char val3[64] = "345678934567893456789345678934567893456789345678934567893456789\0";

int main()
{
	printf("test_loa: Generating keys...\n");
	uint8_t *init_master_key = octo_keygen();
	uint8_t *new_master_key = octo_keygen();
	printf("test_loa: Creating test loa_dict...\n");
	octo_dict_loa_t *test_loa = octo_loa_init(8, 64, 128, init_master_key);
	if(test_loa == NULL)
	{
		printf("test_loa: FAILED: octo_loa_init returned NULL\n");
		return 1;
	}
	octo_loa_stats_msg(test_loa);
	printf("test_loa: Doing test inserts...\n");
	if(octo_loa_insert(key1, val1, (const octo_dict_loa_t *)test_loa) > 0)
	{
		printf("test_loa: FAILED: octo_loa_insert returned error code inserting key \"abcdefg\\0\"\n");
		return 1;
	}
	if(octo_loa_insert(key2, val2, (const octo_dict_loa_t *)test_loa) > 0)
	{
		printf("test_loa: FAILED: octo_loa_insert returned error code inserting key \"bcdefgh\\0\"\n");
		return 1;
	}
	if(octo_loa_insert(key3, val3, (const octo_dict_loa_t *)test_loa) > 0)
	{
		printf("test_loa: FAILED: octo_loa_insert returned error code inserting key \"cdefghi\\0\"\n");
		return 1;
	}
	printf("test_loa: Poking inserted records...\n");
	if(!(octo_loa_poke(key1, (const octo_dict_loa_t *)test_loa)))
	{
		printf("test_loa: FAILED: octo_loa_poke couldn't find test key \"abcdefg\\0\"\n");
		return 1;
	}
	if(!(octo_loa_poke(key2, (const octo_dict_loa_t *)test_loa)))
	{
		printf("test_loa: FAILED: octo_loa_poke couldn't find test key \"bcdefgh\\0\"\n");
		return 1;
	}
	if(!(octo_loa_poke(key3, (const octo_dict_loa_t *)test_loa)))
	{
		printf("test_loa: FAILED: octo_loa_poke couldn't find test key \"cdefghi\\0\"\n");
		return 1;
	}
	printf("test_loa: Poking non-existent record...\n");
	if(octo_loa_poke("zfeuids\n", (const octo_dict_loa_t *)test_loa))
	{
		printf("test_loa: FAILED: octo_loa_poke found non-existent key\n");
		return 1;
	}
	printf("test_loa: Fetching inserted records \"safely\"...\n");
	void *output1 = octo_loa_fetch_safe(key1, (const octo_dict_loa_t *)test_loa);
	void *output2 = octo_loa_fetch_safe(key2, (const octo_dict_loa_t *)test_loa);
	void *output3 = octo_loa_fetch_safe(key3, (const octo_dict_loa_t *)test_loa);
	if(output1 == NULL || output2 == NULL || output3 == NULL)
	{
		printf("test_loa: FAILED: octo_loa_fetch_safe returned NULL\n");
		return 1;
	}
	if(output1 == (void *)test_loa || output2 == (void *)test_loa || output3 == (void *)test_loa)
	{
		printf("test_loa: FAILED: octo_loa_fetch_safe couldn't find test value\n");
		return 1;
	}
	printf("test_loa: Checking for correct values...\n");
	if(memcmp(val1, output1, 64) != 0)
	{
		printf("test_loa: FAILED: octo_loa_fetch_safe returned pointer to incorrect value for key \"abcdefg\\0\"\n");
		return 1;
	}
	if(memcmp(val2, output2, 64) != 0)
	{
		printf("test_loa: FAILED: octo_loa_fetch_safe returned pointer to incorrect value for key \"bcdefgh\\0\"\n");
		return 1;
	}
	if(memcmp(val3, output3, 64) != 0)
	{
		printf("test_loa: FAILED: octo_loa_fetch_safe returned pointer to incorrect value for key \"cdefghi\\0\"\n");
		return 1;
	}
	free(output1);
	free(output2);
	free(output3);
	printf("test_loa: Fetching inserted records \"unsafely\"...\n");
	output1 = octo_loa_fetch(key1, (const octo_dict_loa_t *)test_loa);
	output2 = octo_loa_fetch(key2, (const octo_dict_loa_t *)test_loa);
	output3 = octo_loa_fetch(key3, (const octo_dict_loa_t *)test_loa);
	if(output1 == NULL || output2 == NULL || output3 == NULL)
	{
		printf("test_loa: FAILED: octo_loa_fetch returned NULL\n");
		return 1;
	}
	if(output1 == (void *)test_loa || output2 == (void *)test_loa || output3 == (void *)test_loa)
	{
		printf("test_loa: FAILED: octo_loa_fetch couldn't find test value\n");
		return 1;
	}
	printf("test_loa: Checking for correct values...\n");
	if(memcmp(val1, output1, 64) != 0)
	{
		printf("test_loa: FAILED: octo_loa_fetch returned pointer to incorrect value for key \"abcdefg\\0\"\n");
		return 1;
	}
	if(memcmp(val2, output2, 64) != 0)
	{
		printf("test_loa: FAILED: octo_loa_fetch returned pointer to incorrect value for key \"bcdefgh\\0\"\n");
		return 1;
	}
	if(memcmp(val3, output3, 64) != 0)
	{
		printf("test_loa: FAILED: octo_loa_fetch returned pointer to incorrect value for key \"cdefghi\\0\"\n");
		return 1;
	}
	printf("test_loa: Deleting record...\n");
	if(octo_loa_delete(key1, (const octo_dict_loa_t *)test_loa) != 1)
	{
		printf("test_loa: FAILED: octo_loa_delete returned 0, deletion failed\n");
		return 1;
	}
	printf("test_loa: Looking up deleted key...\n");
	void *error_output = octo_loa_fetch(key1, (const octo_dict_loa_t *)test_loa);
	if(error_output == NULL)
	{
		printf("test_loa: FAILED: octo_loa_fetch returned NULL\n");
		return 1;
	}
	if(error_output != (void *)test_loa)
	{
		printf("test_loa: FAILED: octo_loa_fetch reported hit for non-existent key\n");
		return 1;
	}
	printf("test_loa: Re-inserting deleted record...\n");
	if(octo_loa_insert(key1, val1, (const octo_dict_loa_t *)test_loa) != 0)
	{
		printf("test_loa: FAILED: octo_loa_insert failed to re-insert deleted record\n");
		return 1;
	}
	octo_loa_stats_msg(test_loa);
	printf("test_loa: Rehashing dict...\n");
	test_loa = octo_loa_rehash(test_loa, test_loa->keylen, test_loa->vallen, 3, new_master_key);
	if(test_loa == NULL)
	{
		printf("test_loa: FAILED: octo_loa_rehash returned NULL\n");
		return 1;
	}
	octo_loa_stats_msg(test_loa);
	printf("test_loa: Poking inserted records...\n");
	if(!(octo_loa_poke(key1, (const octo_dict_loa_t *)test_loa)))
	{
		printf("test_loa: FAILED: octo_loa_poke couldn't find test value\n");
		return 1;
	}
	if(!(octo_loa_poke(key2, (const octo_dict_loa_t *)test_loa)))
	{
		printf("test_loa: FAILED: octo_loa_poke couldn't find test value\n");
		return 1;
	}
	if(!(octo_loa_poke(key3, (const octo_dict_loa_t *)test_loa)))
	{
		printf("test_loa: FAILED: octo_loa_poke couldn't find test value\n");
		return 1;
	}
	printf("test_loa: Poking non-existent record...\n");
	if(octo_loa_poke("zfeuids\n", (const octo_dict_loa_t *)test_loa))
	{
		printf("test_loa: FAILED: octo_loa_poke found non-existent key\n");
		return 1;
	}
	printf("test_loa: Fetching inserted records \"safely\"...\n");
	output1 = octo_loa_fetch_safe(key1, (const octo_dict_loa_t *)test_loa);
	output2 = octo_loa_fetch_safe(key2, (const octo_dict_loa_t *)test_loa);
	output3 = octo_loa_fetch_safe(key3, (const octo_dict_loa_t *)test_loa);
	if(output1 == NULL || output2 == NULL || output3 == NULL)
	{
		printf("test_loa: FAILED: octo_loa_fetch_safe returned NULL\n");
		return 1;
	}
	if(output1 == (void *)test_loa || output2 == (void *)test_loa || output3 == (void *)test_loa)
	{
		printf("test_loa: FAILED: octo_loa_fetch_safe couldn't find test value\n");
		return 1;
	}
	printf("test_loa: Checking for correct values...\n");
	if(memcmp(val1, output1, 64) != 0)
	{
		printf("test_loa: FAILED: octo_loa_fetch_safe returned pointer to incorrect value for key \"abcdefg\\0\"\n");
		return 1;
	}
	if(memcmp(val2, output2, 64) != 0)
	{
		printf("test_loa: FAILED: octo_loa_fetch_safe returned pointer to incorrect value for key \"bcdefgh\\0\"\n");
		return 1;
	}
	if(memcmp(val3, output3, 64) != 0)
	{
		printf("test_loa: FAILED: octo_loa_fetch_safe returned pointer to incorrect value for key \"cdefghi\\0\"\n");
		return 1;
	}
	free(output1);
	free(output2);
	free(output3);
	printf("test_loa: Fetching inserted records \"unsafely\"...\n");
	output1 = octo_loa_fetch(key1, (const octo_dict_loa_t *)test_loa);
	output2 = octo_loa_fetch(key2, (const octo_dict_loa_t *)test_loa);
	output3 = octo_loa_fetch(key3, (const octo_dict_loa_t *)test_loa);
	if(output1 == NULL || output2 == NULL || output3 == NULL)
	{
		printf("test_loa: FAILED: octo_loa_fetch returned NULL\n");
		return 1;
	}
	if(output1 == (void *)test_loa || output2 == (void *)test_loa || output3 == (void *)test_loa)
	{
		printf("test_loa: FAILED: octo_loa_fetch couldn't find test value\n");
		return 1;
	}
	printf("test_loa: Checking for correct values...\n");
	if(memcmp(val1, output1, 64) != 0)
	{
		printf("test_loa: FAILED: octo_loa_fetch returned pointer to incorrect value for key \"abcdefg\\0\"\n");
		return 1;
	}
	if(memcmp(val2, output2, 64) != 0)
	{
		printf("test_loa: FAILED: octo_loa_fetch returned pointer to incorrect value for key \"bcdefgh\\0\"\n");
		return 1;
	}
	if(memcmp(val3, output3, 64) != 0)
	{
		printf("test_loa: FAILED: octo_loa_fetch returned pointer to incorrect value for key \"cdefghi\\0\"\n");
		return 1;
	}
	printf("test_loa: Deleting record...\n");
	if(octo_loa_delete(key2, (const octo_dict_loa_t *)test_loa) != 1)
	{
		printf("test_loa: FAILED: octo_loa_delete returned 0, deletion failed\n");
		return 1;
	}
	printf("test_loa: Looking up deleted key...\n");
	error_output = octo_loa_fetch(key2, (const octo_dict_loa_t *)test_loa);
	if(error_output == NULL)
	{
		printf("test_loa: FAILED: octo_loa_fetch returned NULL\n");
		return 1;
	}
	if(error_output != (void *)test_loa)
	{
		printf("test_loa: FAILED: octo_loa_fetch reported hit for non-existent key\n");
		return 1;
	}
	printf("test_loa: Re-inserting deleted record...\n");
	if(octo_loa_insert(key2, val2, (const octo_dict_loa_t *)test_loa) != 0)
	{
		printf("test_loa: FAILED: octo_loa_insert failed to re-insert deleted record\n");
		return 1;
	}
	printf("test_loa: \"Safely\" rehashing dict...\n");
	octo_dict_loa_t *test_loa_safe = octo_loa_rehash_safe(test_loa, test_loa->keylen, test_loa->vallen, 4096, new_master_key);
	if(test_loa_safe == NULL)
	{
		printf("test_loa: FAILED: octo_loa_rehash_safe returned NULL\n");
		return 1;
	}
	printf("test_loa: Deleting old dict...\n");
	octo_loa_free(test_loa);
	octo_loa_stats_msg(test_loa_safe);
	printf("test_loa: Poking inserted records...\n");
	if(!(octo_loa_poke(key1, (const octo_dict_loa_t *)test_loa_safe)))
	{
		printf("test_loa: FAILED: octo_loa_poke couldn't find test value\n");
		return 1;
	}
	if(!(octo_loa_poke(key2, (const octo_dict_loa_t *)test_loa_safe)))
	{
		printf("test_loa: FAILED: octo_loa_poke couldn't find test value\n");
		return 1;
	}
	if(!(octo_loa_poke(key3, (const octo_dict_loa_t *)test_loa_safe)))
	{
		printf("test_loa: FAILED: octo_loa_poke couldn't find test value\n");
		return 1;
	}
	printf("test_loa: Poking non-existent record...\n");
	if(octo_loa_poke("zfeuids\n", (const octo_dict_loa_t *)test_loa_safe))
	{
		printf("test_loa: FAILED: octo_loa_poke found non-existent key\n");
		return 1;
	}
	printf("test_loa: Fetching inserted records \"safely\"...\n");
	output1 = octo_loa_fetch_safe(key1, (const octo_dict_loa_t *)test_loa_safe);
	output2 = octo_loa_fetch_safe(key2, (const octo_dict_loa_t *)test_loa_safe);
	output3 = octo_loa_fetch_safe(key3, (const octo_dict_loa_t *)test_loa_safe);
	if(output1 == NULL || output2 == NULL || output3 == NULL)
	{
		printf("test_loa: FAILED: octo_loa_fetch_safe returned NULL\n");
		return 1;
	}
	if(output1 == (void *)test_loa_safe || output2 == (void *)test_loa_safe || output3 == (void *)test_loa_safe)
	{
		printf("test_loa: FAILED: octo_loa_fetch_safe couldn't find test value\n");
		return 1;
	}
	printf("test_loa: Checking for correct values...\n");
	if(memcmp(val1, output1, 64) != 0)
	{
		printf("test_loa: FAILED: octo_loa_fetch_safe returned pointer to incorrect value for key \"abcdefg\\0\"\n");
		return 1;
	}
	if(memcmp(val2, output2, 64) != 0)
	{
		printf("test_loa: FAILED: octo_loa_fetch_safe returned pointer to incorrect value for key \"bcdefgh\\0\"\n");
		return 1;
	}
	if(memcmp(val3, output3, 64) != 0)
	{
		printf("test_loa: FAILED: octo_loa_fetch_safe returned pointer to incorrect value for key \"cdefghi\\0\"\n");
		return 1;
	}
	free(output1);
	free(output2);
	free(output3);
	printf("test_loa: Fetching inserted records \"unsafely\"...\n");
	output1 = octo_loa_fetch(key1, (const octo_dict_loa_t *)test_loa_safe);
	output2 = octo_loa_fetch(key2, (const octo_dict_loa_t *)test_loa_safe);
	output3 = octo_loa_fetch(key3, (const octo_dict_loa_t *)test_loa_safe);
	if(output1 == NULL || output2 == NULL || output3 == NULL)
	{
		printf("test_loa: FAILED: octo_loa_fetch returned NULL\n");
		return 1;
	}
	if(output1 == (void *)test_loa_safe || output2 == (void *)test_loa_safe || output3 == (void *)test_loa_safe)
	{
		printf("test_loa: FAILED: octo_loa_fetch couldn't find test value\n");
		return 1;
	}
	printf("test_loa: Checking for correct values...\n");
	if(memcmp(val1, output1, 64) != 0)
	{
		printf("test_loa: FAILED: octo_loa_fetch returned pointer to incorrect value for key \"abcdefg\\0\"\n");
		return 1;
	}
	if(memcmp(val2, output2, 64) != 0)
	{
		printf("test_loa: FAILED: octo_loa_fetch returned pointer to incorrect value for key \"bcdefgh\\0\"\n");
		return 1;
	}
	if(memcmp(val3, output3, 64) != 0)
	{
		printf("test_loa: FAILED: octo_loa_fetch returned pointer to incorrect value for key \"cdefghi\\0\"\n");
		return 1;
	}
	printf("test_loa: Deleting record...\n");
	if(octo_loa_delete(key3, (const octo_dict_loa_t *)test_loa_safe) != 1)
	{
		printf("test_loa: FAILED: octo_loa_delete returned 0, deletion failed\n");
		return 1;
	}
	printf("test_loa: Looking up deleted key...\n");
	error_output = octo_loa_fetch(key3, (const octo_dict_loa_t *)test_loa_safe);
	if(error_output == NULL)
	{
		printf("test_loa: FAILED: octo_loa_fetch returned NULL\n");
		return 1;
	}
	if(error_output != (void *)test_loa_safe)
	{
		printf("test_loa: FAILED: octo_loa_fetch reported hit for non-existent key\n");
		return 1;
	}
	printf("test_loa: Re-inserting deleted record...\n");
	if(octo_loa_insert(key3, val3, (const octo_dict_loa_t *)test_loa_safe) != 0)
	{
		printf("test_loa: FAILED: octo_loa_insert failed to re-insert deleted record\n");
		return 1;
	}
	printf("test_loa: Deleting loa_dict...\n");
	octo_loa_free(test_loa_safe);
	free(init_master_key);
	free(new_master_key);
	printf("test_loa: SUCCESS!\n");
	return 0;
}
