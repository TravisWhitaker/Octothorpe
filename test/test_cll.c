// libocto Copyright (C) Travis Whitaker 2013

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>

#include <octo/types.h>
#include <octo/keygen.h>
#include <octo/cll.h>

char key1[8] = "abcdefg\0";
char key2[8] = "bcdefgh\0";
char key3[8] = "cdefghi\0";
char val1[64] = "123456781234567812345678123456781234567812345678123456781234567\0";
char val2[64] = "234567892345678923456789234567892345678923456789234567892345678\0";
char val3[64] = "345678934567893456789345678934567893456789345678934567893456789\0";

int main()
{
	printf("test_cll: Generating keys...\n");
	uint8_t *init_master_key = octo_keygen();
	uint8_t *new_master_key = octo_keygen();
	printf("test_cll: Creating test cll_dict...\n");
	octo_dict_cll_t *test_cll = octo_cll_init(8, 64, 1, init_master_key);
	if(test_cll == NULL)
	{
		printf("test_cll: FAILED: octo_cll_init returned NULL\n");
		return 1;
	}
	octo_cll_stats_msg(test_cll);
	printf("test_cll: Doing test inserts...\n");
	if(octo_cll_insert(key1, val1, (const octo_dict_cll_t *)test_cll) > 0)
	{
		printf("test_cll: FAILED: octo_cll_insert returned error code inserting key \"abcdefg\\0\"\n");
		return 1;
	}
	if(octo_cll_insert(key2, val2, (const octo_dict_cll_t *)test_cll) > 0)
	{
		printf("test_cll: FAILED: octo_cll_insert returned error code inserting key \"bcdefgh\\0\"\n");
		return 1;
	}
	if(octo_cll_insert(key3, val3, (const octo_dict_cll_t *)test_cll) > 0)
	{
		printf("test_cll: FAILED: octo_cll_insert returned error code inserting key \"cdefghi\\0\"\n");
		return 1;
	}
	printf("test_cll: Poking inserted records...\n");
	if(!(octo_cll_poke(key1, (const octo_dict_cll_t *)test_cll)))
	{
		printf("test_cll: FAILED: octo_cll_poke couldn't find test key \"abcdefg\\0\"\n");
		return 1;
	}
	if(!(octo_cll_poke(key2, (const octo_dict_cll_t *)test_cll)))
	{
		printf("test_cll: FAILED: octo_cll_poke couldn't find test key \"bcdefgh\\0\"\n");
		return 1;
	}
	if(!(octo_cll_poke(key3, (const octo_dict_cll_t *)test_cll)))
	{
		printf("test_cll: FAILED: octo_cll_poke couldn't find test key \"cdefghi\\0\"\n");
		return 1;
	}
	printf("test_cll: Poking non-existent record...\n");
	if(octo_cll_poke("zfeuids\n", (const octo_dict_cll_t *)test_cll))
	{
		printf("test_cll: FAILED: octo_cll_poke found non-existent key\n");
		return 1;
	}
	printf("test_cll: Fetching inserted records...\n");
	void *output1 = octo_cll_fetch(key1, (const octo_dict_cll_t *)test_cll);
	void *output2 = octo_cll_fetch(key2, (const octo_dict_cll_t *)test_cll);
	void *output3 = octo_cll_fetch(key3, (const octo_dict_cll_t *)test_cll);
	if(output1 == NULL || output2 == NULL || output3 == NULL)
	{
		printf("test_cll: FAILED: octo_cll_fetch returned NULL\n");
		return 1;
	}
	if(output1 == (void *)test_cll || output2 == (void *)test_cll || output3 == (void *)test_cll)
	{
		printf("test_cll: FAILED: octo_cll_fetch couldn't find test value\n");
		return 1;
	}
	printf("test_cll: Checking for correct values...\n");
	if(memcmp(val1, output1, 64) != 0)
	{
		printf("test_cll: FAILED: octo_cll_fetch returned pointer to incorrect value for key \"abcdefg\\0\"\n");
		return 1;
	}
	if(memcmp(val2, output2, 64) != 0)
	{
		printf("test_cll: FAILED: octo_cll_fetch returned pointer to incorrect value for key \"bcdefgh\\0\"\n");
		return 1;
	}
	if(memcmp(val3, output3, 64) != 0)
	{
		printf("test_cll: FAILED: octo_cll_fetch returned pointer to incorrect value for key \"cdefghi\\0\"\n");
		return 1;
	}
	free(output1);
	free(output2);
	free(output3);
	printf("test_cll: Looking up non-existent key...\n");
	void *error_output = octo_cll_fetch("zxcvbde\0", (const octo_dict_cll_t *)test_cll);
	if(error_output == NULL)
	{
		printf("test_cll: FAILED: octo_cll_fetch returned NULL\n");
		return 1;
	}
	if(error_output != (void *)test_cll)
	{
		printf("test_cll: FAILED: octo_cll_fetch reported hit for non-existent key\n");
		return 1;
	}
	octo_cll_stats_msg(test_cll);
	printf("test_cll: Rehashing dict...\n");
	test_cll = octo_cll_rehash(test_cll, test_cll->keylen, test_cll->vallen, 1, new_master_key);
	octo_cll_stats_msg(test_cll);
	printf("test_cll: Poking inserted records...\n");
	if(!(octo_cll_poke(key1, (const octo_dict_cll_t *)test_cll)))
	{
		printf("test_cll: FAILED: octo_cll_poke couldn't find test value\n");
		return 1;
	}
	if(!(octo_cll_poke(key2, (const octo_dict_cll_t *)test_cll)))
	{
		printf("test_cll: FAILED: octo_cll_poke couldn't find test value\n");
		return 1;
	}
	if(!(octo_cll_poke(key3, (const octo_dict_cll_t *)test_cll)))
	{
		printf("test_cll: FAILED: octo_cll_poke couldn't find test value\n");
		return 1;
	}
	printf("test_cll: Poking non-existent record...\n");
	if(octo_cll_poke("zfeuids\n", (const octo_dict_cll_t *)test_cll))
	{
		printf("test_cll: FAILED: octo_cll_poke found non-existent key\n");
		return 1;
	}
	printf("test_cll: Fetching inserted records...\n");
	output1 = octo_cll_fetch(key1, (const octo_dict_cll_t *)test_cll);
	output2 = octo_cll_fetch(key2, (const octo_dict_cll_t *)test_cll);
	output3 = octo_cll_fetch(key3, (const octo_dict_cll_t *)test_cll);
	if(output1 == NULL || output2 == NULL || output3 == NULL)
	{
		printf("test_cll: FAILED: octo_cll_fetch returned NULL\n");
		return 1;
	}
	if(output1 == (void *)test_cll || output2 == (void *)test_cll || output3 == (void *)test_cll)
	{
		printf("test_cll: FAILED: octo_cll_fetch couldn't find test value\n");
		return 1;
	}
	printf("test_cll: Checking for correct values...\n");
	if(memcmp(val1, output1, 64) != 0)
	{
		printf("test_cll: FAILED: octo_cll_fetch returned pointer to incorrect value for key \"abcdefg\\0\"\n");
		return 1;
	}
	if(memcmp(val2, output2, 64) != 0)
	{
		printf("test_cll: FAILED: octo_cll_fetch returned pointer to incorrect value for key \"bcdefgh\\0\"\n");
		return 1;
	}
	if(memcmp(val3, output3, 64) != 0)
	{
		printf("test_cll: FAILED: octo_cll_fetch returned pointer to incorrect value for key \"cdefghi\\0\"\n");
		return 1;
	}
	free(output1);
	free(output2);
	free(output3);
	printf("test_cll: Looking up non-existent key...\n");
	error_output = octo_cll_fetch("zxcvbde\n", (const octo_dict_cll_t *)test_cll);
	if(error_output == NULL)
	{
		printf("test_cll: FAILED: octo_cll_fetch returned NULL\n");
		return 1;
	}
	if(error_output != (void *)test_cll)
	{
		printf("test_cll: FAILED: octo_cll_fetch reported hit for non-existent key\n");
		return 1;
	}
	if(test_cll == NULL)
	{
		printf("test_cll: FAILED: octo_cll_rehash returned null\n");
		return 1;
	}
	printf("test_cll: \"Safely\" rehashing dict...\n");
	octo_dict_cll_t *test_cll_safe = octo_cll_rehash_safe(test_cll, test_cll->keylen, test_cll->vallen, 4096, new_master_key);
	printf("test_cll: Deleting old dict...\n");
	octo_cll_delete(test_cll);
	octo_cll_stats_msg(test_cll_safe);
	printf("test_cll: Poking inserted records...\n");
	if(!(octo_cll_poke(key1, (const octo_dict_cll_t *)test_cll_safe)))
	{
		printf("test_cll: FAILED: octo_cll_poke couldn't find test value\n");
		return 1;
	}
	if(!(octo_cll_poke(key2, (const octo_dict_cll_t *)test_cll_safe)))
	{
		printf("test_cll: FAILED: octo_cll_poke couldn't find test value\n");
		return 1;
	}
	if(!(octo_cll_poke(key3, (const octo_dict_cll_t *)test_cll_safe)))
	{
		printf("test_cll: FAILED: octo_cll_poke couldn't find test value\n");
		return 1;
	}
	printf("test_cll: Poking non-existent record...\n");
	if(octo_cll_poke("zfeuids\n", (const octo_dict_cll_t *)test_cll_safe))
	{
		printf("test_cll: FAILED: octo_cll_poke found non-existent key\n");
		return 1;
	}
	printf("test_cll: Fetching inserted records...\n");
	output1 = octo_cll_fetch(key1, (const octo_dict_cll_t *)test_cll_safe);
	output2 = octo_cll_fetch(key2, (const octo_dict_cll_t *)test_cll_safe);
	output3 = octo_cll_fetch(key3, (const octo_dict_cll_t *)test_cll_safe);
	if(output1 == NULL || output2 == NULL || output3 == NULL)
	{
		printf("test_cll: FAILED: octo_cll_fetch returned NULL\n");
		return 1;
	}
	if(output1 == (void *)test_cll_safe || output2 == (void *)test_cll_safe || output3 == (void *)test_cll_safe)
	{
		printf("test_cll: FAILED: octo_cll_fetch couldn't find test value\n");
		return 1;
	}
	printf("test_cll: Checking for correct values...\n");
	if(memcmp(val1, output1, 64) != 0)
	{
		printf("test_cll: FAILED: octo_cll_fetch returned pointer to incorrect value for key \"abcdefg\\0\"\n");
		return 1;
	}
	if(memcmp(val2, output2, 64) != 0)
	{
		printf("test_cll: FAILED: octo_cll_fetch returned pointer to incorrect value for key \"bcdefgh\\0\"\n");
		return 1;
	}
	if(memcmp(val3, output3, 64) != 0)
	{
		printf("test_cll: FAILED: octo_cll_fetch returned pointer to incorrect value for key \"cdefghi\\0\"\n");
		return 1;
	}
	free(output1);
	free(output2);
	free(output3);
	printf("test_cll: Looking up non-existent key...\n");
	error_output = octo_cll_fetch("zxcvbde\n", (const octo_dict_cll_t *)test_cll_safe);
	if(error_output == NULL)
	{
		printf("test_cll: FAILED: octo_cll_fetch returned NULL\n");
		return 1;
	}
	if(error_output != (void *)test_cll_safe)
	{
		printf("test_cll: FAILED: octo_cll_fetch reported hit for non-existent key\n");
		return 1;
	}
	if(test_cll == NULL)
	{
		printf("test_cll: FAILED: octo_cll_rehash returned null\n");
		return 1;
	}
	printf("test_cll: Deleting cll_dict...\n");
	octo_cll_delete(test_cll_safe);
	free(init_master_key);
	free(new_master_key);
	printf("test_cll: SUCCESS!\n");
	return 0;
}
