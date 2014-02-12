// libocto Copyright (C) Travis Whitaker 2013-2014

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>

#include <octo/types.h>
#include <octo/keygen.h>
#include <octo/debug.h>

int main()
{
	DEBUG_MSG("test_keygen: Generating key...\n");
	uint8_t *test_key = octo_keygen();
	DEBUG_MSG("test_keygen: Got key ");
	char buf[4];
	for(unsigned int i = 0; i < 16; i++)
	{
		snprintf(buf, 4, "%.2x", test_key[i]);
		DEBUG_MSG(buf);
	}
	free(test_key);
	printf("\ntest_keygen: SUCCESS!\n");
	return 0;
}
