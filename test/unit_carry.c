// libocto Copyright (C) Travis Whitaker 2013-2014

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>

#include <octo/types.h>
#include <octo/keygen.h>
#include <octo/carry.h>
#include <octo/debug.h>

char key1[8] = "abcdefg\0";
char key2[8] = "bcdefgh\0";
char key3[8] = "cdefghi\0";
char val1[64] = "123456781234567812345678123456781234567812345678123456781234567\0";
char val2[64] = "234567892345678923456789234567892345678923456789234567892345678\0";
char val3[64] = "345678934567893456789345678934567893456789345678934567893456789\0";

int main()
{
	DEBUG_MSG("test_carry: Generating keys...");
	uint8_t *init_master_key = octo_keygen();
	uint8_t *new_master_key = octo_keygen();
	DEBUG_MSG("test_carry: Creating test carry_dict...");
	octo_dict_carry_t *test_carry = octo_carry_init(8, 64, 128, 1, init_master_key);
	if(test_carry == NULL)
	{
		printf("test_carry: FAILED: octo_carry_init returned NULL\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Doing test inserts...");
	if(octo_carry_insert(key1, val1, (const octo_dict_carry_t *)test_carry) > 0)
	{
		printf("test_carry: FAILED: octo_carry_insert returned error code inserting key \"abcdefg\\0\"\n");
		return 1;
	}
	if(octo_carry_insert(key2, val2, (const octo_dict_carry_t *)test_carry) > 0)
	{
		printf("test_carry: FAILED: octo_carry_insert returned error code inserting key \"bcdefgh\\0\"\n");
		return 1;
	}
	if(octo_carry_insert(key3, val3, (const octo_dict_carry_t *)test_carry) > 0)
	{
		printf("test_carry: FAILED: octo_carry_insert returned error code inserting key \"cdefghi\\0\"\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Poking inserted records...");
	if(!(octo_carry_poke(key1, (const octo_dict_carry_t *)test_carry)))
	{
		printf("test_carry: FAILED: octo_carry_poke couldn't find test key \"abcdefg\\0\"\n");
		return 1;
	}
	if(!(octo_carry_poke(key2, (const octo_dict_carry_t *)test_carry)))
	{
		printf("test_carry: FAILED: octo_carry_poke couldn't find test key \"bcdefgh\\0\"\n");
		return 1;
	}
	if(!(octo_carry_poke(key3, (const octo_dict_carry_t *)test_carry)))
	{
		printf("test_carry: FAILED: octo_carry_poke couldn't find test key \"cdefghi\\0\"\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Poking non-existent record...");
	if(octo_carry_poke("zfeuids\n", (const octo_dict_carry_t *)test_carry))
	{
		printf("test_carry: FAILED: octo_carry_poke found non-existent key\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Fetching inserted records \"safely\"...");
	void *output1 = octo_carry_fetch_safe(key1, (const octo_dict_carry_t *)test_carry);
	void *output2 = octo_carry_fetch_safe(key2, (const octo_dict_carry_t *)test_carry);
	void *output3 = octo_carry_fetch_safe(key3, (const octo_dict_carry_t *)test_carry);
	if(output1 == NULL || output2 == NULL || output3 == NULL)
	{
		printf("test_carry: FAILED: octo_carry_fetch_safe returned NULL\n");
		return 1;
	}
	if(output1 == (void *)test_carry || output2 == (void *)test_carry || output3 == (void *)test_carry)
	{
		printf("test_carry: FAILED: octo_carry_fetch_safe couldn't find test value\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Checking for correct values...");
	if(memcmp(val1, output1, 64) != 0)
	{
		printf("test_carry: FAILED: octo_carry_fetch_safe returned pointer to incorrect value for key \"abcdefg\\0\"\n");
		return 1;
	}
	if(memcmp(val2, output2, 64) != 0)
	{
		printf("test_carry: FAILED: octo_carry_fetch_safe returned pointer to incorrect value for key \"bcdefgh\\0\"\n");
		return 1;
	}
	if(memcmp(val3, output3, 64) != 0)
	{
		printf("test_carry: FAILED: octo_carry_fetch_safe returned pointer to incorrect value for key \"cdefghi\\0\"\n");
		return 1;
	}
	free(output1);
	free(output2);
	free(output3);
	DEBUG_MSG("test_carry: Fetching inserted records \"unsafely\"...");
	output1 = octo_carry_fetch(key1, (const octo_dict_carry_t *)test_carry);
	output2 = octo_carry_fetch(key2, (const octo_dict_carry_t *)test_carry);
	output3 = octo_carry_fetch(key3, (const octo_dict_carry_t *)test_carry);
	if(output1 == NULL || output2 == NULL || output3 == NULL)
	{
		printf("test_carry: FAILED: octo_carry_fetch returned NULL\n");
		return 1;
	}
	if(output1 == (void *)test_carry || output2 == (void *)test_carry || output3 == (void *)test_carry)
	{
		printf("test_carry: FAILED: octo_carry_fetch couldn't find test value\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Checking for correct values...");
	if(memcmp(val1, output1, 64) != 0)
	{
		printf("test_carry: FAILED: octo_carry_fetch returned pointer to incorrect value for key \"abcdefg\\0\"\n");
		return 1;
	}
	if(memcmp(val2, output2, 64) != 0)
	{
		printf("test_carry: FAILED: octo_carry_fetch returned pointer to incorrect value for key \"bcdefgh\\0\"\n");
		return 1;
	}
	if(memcmp(val3, output3, 64) != 0)
	{
		printf("test_carry: FAILED: octo_carry_fetch returned pointer to incorrect value for key \"cdefghi\\0\"\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Deleting a record...");
	if(octo_carry_delete(key1, (const octo_dict_carry_t *)test_carry) == 0)
	{
		printf("test_carry: FAILED: octo_carry_delete returned 0, deletion failed\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Looking up deleted key...");
	void *error_output = octo_carry_fetch(key1, (const octo_dict_carry_t *)test_carry);
	if(error_output == NULL)
	{
		printf("test_carry: FAILED: octo_carry_fetch returned NULL\n");
		return 1;
	}
	if(error_output != (void *)test_carry)
	{
		printf("test_carry: FAILED: octo_carry_fetch reported hit for non-existent key\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Re-inserting deleted key...");
	if(octo_carry_insert(key1, val1, (const octo_dict_carry_t *)test_carry) != 0)
	{
		printf("test_carry: FAILED: octo_carry_insert failed re-inserting deleted key\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Rehashing dict...");
	test_carry = octo_carry_rehash(test_carry, test_carry->keylen, test_carry->vallen, 1, 1, new_master_key);
	if(test_carry == NULL)
	{
		printf("test_carry: FAILED: octo_carry_rehash returned null\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Poking inserted records...");
	if(!(octo_carry_poke(key1, (const octo_dict_carry_t *)test_carry)))
	{
		printf("test_carry: FAILED: octo_carry_poke couldn't find test value\n");
		return 1;
	}
	if(!(octo_carry_poke(key2, (const octo_dict_carry_t *)test_carry)))
	{
		printf("test_carry: FAILED: octo_carry_poke couldn't find test value\n");
		return 1;
	}
	if(!(octo_carry_poke(key3, (const octo_dict_carry_t *)test_carry)))
	{
		printf("test_carry: FAILED: octo_carry_poke couldn't find test value\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Poking non-existent record...");
	if(octo_carry_poke("zfeuids\n", (const octo_dict_carry_t *)test_carry))
	{
		printf("test_carry: FAILED: octo_carry_poke found non-existent key\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Fetching inserted records \"safely\"...");
	output1 = octo_carry_fetch_safe(key1, (const octo_dict_carry_t *)test_carry);
	output2 = octo_carry_fetch_safe(key2, (const octo_dict_carry_t *)test_carry);
	output3 = octo_carry_fetch_safe(key3, (const octo_dict_carry_t *)test_carry);
	if(output1 == NULL || output2 == NULL || output3 == NULL)
	{
		printf("test_carry: FAILED: octo_carry_fetch_safe returned NULL\n");
		return 1;
	}
	if(output1 == (void *)test_carry || output2 == (void *)test_carry || output3 == (void *)test_carry)
	{
		printf("test_carry: FAILED: octo_carry_fetch_safe couldn't find test value\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Checking for correct values...");
	if(memcmp(val1, output1, 64) != 0)
	{
		printf("test_carry: FAILED: octo_carry_fetch_safe returned pointer to incorrect value for key \"abcdefg\\0\"\n");
		return 1;
	}
	if(memcmp(val2, output2, 64) != 0)
	{
		printf("test_carry: FAILED: octo_carry_fetch_safe returned pointer to incorrect value for key \"bcdefgh\\0\"\n");
		return 1;
	}
	if(memcmp(val3, output3, 64) != 0)
	{
		printf("test_carry: FAILED: octo_carry_fetch_safe returned pointer to incorrect value for key \"cdefghi\\0\"\n");
		return 1;
	}
	free(output1);
	free(output2);
	free(output3);
	DEBUG_MSG("test_carry: Fetching inserted records \"unsafely\"...");
	output1 = octo_carry_fetch(key1, (const octo_dict_carry_t *)test_carry);
	output2 = octo_carry_fetch(key2, (const octo_dict_carry_t *)test_carry);
	output3 = octo_carry_fetch(key3, (const octo_dict_carry_t *)test_carry);
	if(output1 == NULL || output2 == NULL || output3 == NULL)
	{
		printf("test_carry: FAILED: octo_carry_fetch returned NULL\n");
		return 1;
	}
	if(output1 == (void *)test_carry || output2 == (void *)test_carry || output3 == (void *)test_carry)
	{
		printf("test_carry: FAILED: octo_carry_fetch couldn't find test value\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Checking for correct values...");
	if(memcmp(val1, output1, 64) != 0)
	{
		printf("test_carry: FAILED: octo_carry_fetch returned pointer to incorrect value for key \"abcdefg\\0\"\n");
		return 1;
	}
	if(memcmp(val2, output2, 64) != 0)
	{
		printf("test_carry: FAILED: octo_carry_fetch returned pointer to incorrect value for key \"bcdefgh\\0\"\n");
		return 1;
	}
	if(memcmp(val3, output3, 64) != 0)
	{
		printf("test_carry: FAILED: octo_carry_fetch returned pointer to incorrect value for key \"cdefghi\\0\"\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Deleting a record...");
	if(octo_carry_delete(key2, (const octo_dict_carry_t *)test_carry) == 0)
	{
		printf("test_carry: FAILED: octo_carry_delete returned 0, deletion failed\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Looking up deleted key...");
	error_output = octo_carry_fetch(key2, (const octo_dict_carry_t *)test_carry);
	if(error_output == NULL)
	{
		printf("test_carry: FAILED: octo_carry_fetch returned NULL\n");
		return 1;
	}
	if(error_output != (void *)test_carry)
	{
		printf("test_carry: FAILED: octo_carry_fetch reported hit for non-existent key\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Re-inserting deleted key...");
	if(octo_carry_insert(key2, val2, (const octo_dict_carry_t *)test_carry) != 0)
	{
		printf("test_carry: FAILED: octo_carry_insert failed re-inserting deleted key\n");
		return 1;
	}
	DEBUG_MSG("test_carry: \"Safely\" rehashing dict...");
	octo_dict_carry_t *test_carry_safe = octo_carry_rehash_safe(test_carry, test_carry->keylen, test_carry->vallen, 4096, 3, new_master_key);
	if(test_carry_safe == NULL)
	{
		printf("test_carry: FAILED: octo_carry_rehash_safe returned null\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Deleting old dict...");
	octo_carry_free(test_carry);
	DEBUG_MSG("test_carry: Poking inserted records...");
	if(!(octo_carry_poke(key1, (const octo_dict_carry_t *)test_carry_safe)))
	{
		printf("test_carry: FAILED: octo_carry_poke couldn't find test value\n");
		return 1;
	}
	if(!(octo_carry_poke(key2, (const octo_dict_carry_t *)test_carry_safe)))
	{
		printf("test_carry: FAILED: octo_carry_poke couldn't find test value\n");
		return 1;
	}
	if(!(octo_carry_poke(key3, (const octo_dict_carry_t *)test_carry_safe)))
	{
		printf("test_carry: FAILED: octo_carry_poke couldn't find test value\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Poking non-existent record...");
	if(octo_carry_poke("zfeuids\n", (const octo_dict_carry_t *)test_carry_safe))
	{
		printf("test_carry: FAILED: octo_carry_poke found non-existent key\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Fetching inserted records \"safely\"...");
	output1 = octo_carry_fetch_safe(key1, (const octo_dict_carry_t *)test_carry_safe);
	output2 = octo_carry_fetch_safe(key2, (const octo_dict_carry_t *)test_carry_safe);
	output3 = octo_carry_fetch_safe(key3, (const octo_dict_carry_t *)test_carry_safe);
	if(output1 == NULL || output2 == NULL || output3 == NULL)
	{
		printf("test_carry: FAILED: octo_carry_fetch_safe returned NULL\n");
		return 1;
	}
	if(output1 == (void *)test_carry_safe || output2 == (void *)test_carry_safe || output3 == (void *)test_carry_safe)
	{
		printf("test_carry: FAILED: octo_carry_fetch_safe couldn't find test value\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Checking for correct values...");
	if(memcmp(val1, output1, 64) != 0)
	{
		printf("test_carry: FAILED: octo_carry_fetch_safe returned pointer to incorrect value for key \"abcdefg\\0\"\n");
		return 1;
	}
	if(memcmp(val2, output2, 64) != 0)
	{
		printf("test_carry: FAILED: octo_carry_fetch_safe returned pointer to incorrect value for key \"bcdefgh\\0\"\n");
		return 1;
	}
	if(memcmp(val3, output3, 64) != 0)
	{
		printf("test_carry: FAILED: octo_carry_fetch_safe returned pointer to incorrect value for key \"cdefghi\\0\"\n");
		return 1;
	}
	free(output1);
	free(output2);
	free(output3);
	DEBUG_MSG("test_carry: Fetching inserted records \"unsafely\"...");
	output1 = octo_carry_fetch(key1, (const octo_dict_carry_t *)test_carry_safe);
	output2 = octo_carry_fetch(key2, (const octo_dict_carry_t *)test_carry_safe);
	output3 = octo_carry_fetch(key3, (const octo_dict_carry_t *)test_carry_safe);
	if(output1 == NULL || output2 == NULL || output3 == NULL)
	{
		printf("test_carry: FAILED: octo_carry_fetch returned NULL\n");
		return 1;
	}
	if(output1 == (void *)test_carry_safe || output2 == (void *)test_carry_safe || output3 == (void *)test_carry_safe)
	{
		printf("test_carry: FAILED: octo_carry_fetch couldn't find test value\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Checking for correct values...");
	if(memcmp(val1, output1, 64) != 0)
	{
		printf("test_carry: FAILED: octo_carry_fetch returned pointer to incorrect value for key \"abcdefg\\0\"\n");
		return 1;
	}
	if(memcmp(val2, output2, 64) != 0)
	{
		printf("test_carry: FAILED: octo_carry_fetch returned pointer to incorrect value for key \"bcdefgh\\0\"\n");
		return 1;
	}
	if(memcmp(val3, output3, 64) != 0)
	{
		printf("test_carry: FAILED: octo_carry_fetch returned pointer to incorrect value for key \"cdefghi\\0\"\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Deleting a record...");
	if(octo_carry_delete(key3, (const octo_dict_carry_t *)test_carry_safe) == 0)
	{
		printf("test_carry: FAILED: octo_carry_delete returned 0, deletion failed\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Looking up deleted key...");
	error_output = octo_carry_fetch(key3, (const octo_dict_carry_t *)test_carry_safe);
	if(error_output == NULL)
	{
		printf("test_carry: FAILED: octo_carry_fetch returned NULL\n");
		return 1;
	}
	if(error_output != (void *)test_carry_safe)
	{
		printf("test_carry: FAILED: octo_carry_fetch reported hit for non-existent key\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Re-inserting deleted key...");
	if(octo_carry_insert(key3, val3, (const octo_dict_carry_t *)test_carry_safe) != 0)
	{
		printf("test_carry: FAILED: octo_carry_insert failed re-inserting deleted key\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Cloning carry_dict...");
	octo_dict_carry_t *test_carry_clone = octo_carry_clone(test_carry_safe);
	if(test_carry_clone == NULL)
	{
		printf("test_carry: FAILED: octo_carry_clone returned NULL\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Fetching inserted records from clone...");
	output1 = octo_carry_fetch(key1, (const octo_dict_carry_t *)test_carry_clone);
	output2 = octo_carry_fetch(key2, (const octo_dict_carry_t *)test_carry_clone);
	output3 = octo_carry_fetch(key3, (const octo_dict_carry_t *)test_carry_clone);
	if(output1 == NULL || output2 == NULL || output3 == NULL)
	{
		printf("test_carry: FAILED: octo_carry_fetch returned NULL\n");
		return 1;
	}
	if(output1 == (void *)test_carry_safe || output2 == (void *)test_carry_safe || output3 == (void *)test_carry_safe)
	{
		printf("test_carry: FAILED: octo_carry_fetch couldn't find test value\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Checking for correct values...");
	if(memcmp(val1, output1, 64) != 0)
	{
		printf("test_carry: FAILED: octo_carry_fetch returned pointer to incorrect value for key \"abcdefg\\0\"\n");
		return 1;
	}
	if(memcmp(val2, output2, 64) != 0)
	{
		printf("test_carry: FAILED: octo_carry_fetch returned pointer to incorrect value for key \"bcdefgh\\0\"\n");
		return 1;
	}
	if(memcmp(val3, output3, 64) != 0)
	{
		printf("test_carry: FAILED: octo_carry_fetch returned pointer to incorrect value for key \"cdefghi\\0\"\n");
		return 1;
	}
	DEBUG_MSG("test_carry: Deleting carry_dict...");
	octo_carry_free(test_carry_safe);
	octo_carry_free(test_carry_clone);
	free(init_master_key);
	free(new_master_key);
	printf("test_carry: SUCCESS!\n");
	return 0;
}
