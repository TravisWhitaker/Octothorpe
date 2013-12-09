// libocto Copyright (C) Travis Whitaker 2013

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <errno.h>

#include <octo/types.h>
#include <octo/debug.h>
#include <octo/keygen.h>

uint8_t *octo_keygen()
{
	uint8_t *output = malloc(sizeof(uint8_t) * 16);
	if(output == NULL)
	{
		DEBUG_MSG("malloc failed allocating output array");
		errno = ENOMEM;
		return NULL;
	}
	char *randstate = malloc(256);
	if(randstate == NULL)
	{
		DEBUG_MSG("malloc failed allocating random state array");
		errno = ENOMEM;
		return NULL;
	}
	initstate((unsigned int)time(NULL), randstate, 256);
	for(unsigned int i = 0; i < 16; i++)
	{
		output[i] = (uint8_t)random();
	}
	free(randstate);
	return output;
}
