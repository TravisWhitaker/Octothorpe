// libocto Copyright (C) Travis Whitaker 2013-2014

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>

#include <octo/types.h>
#include <octo/keygen.h>

int main()
{
	printf("test_keygen: Generating key...\n");
	uint8_t *test_key = octo_keygen();
	printf("test_keygen: Got key ");
	for(unsigned int i = 0; i < 16; i++)
	{
		printf("%.2x ", test_key[i]);
	}
	free(test_key);
	printf("\ntest_keygen: SUCCESS!\n");
	return 0;
}
