// libocto Copyright (C) Travis Whitaker 2013

#include <stdio.h>
#include <stdlib.h>

#include <errno.h>

#include <octo/types.h>
#include <octo/carry.h>

int main()
{
	uint8_t init_master_key[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 'a', 'b', 'c', 'd', 'e', 'f'};
	octo_dict_carry_t *test_carry = octo_carry_init(8, 64, 10000000, 2,init_master_key);
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
	octo_carry_delete(test_carry);
	printf("test_carry: SUCCESS!\n");
	return 0;
}
