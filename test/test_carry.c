// libocto Copyright (C) Travis Whitaker 2013

#include <stdio.h>
#include <stdlib.h>

#include <errno.h>

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
	octo_carry_delete(test_carry);
	printf("test_carry: SUCCESS!\n");
	return 0;
}
