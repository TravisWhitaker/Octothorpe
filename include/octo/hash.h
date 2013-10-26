// libocto Copyright (C) Travis Whitaker 2013

#ifndef OCTO_HASH_H
#define OCTO_HASH_H

// libocto's dual key hash function:
void octo_hash(const unsigned char *input, unsigned long int input_length, unsigned char *output, const unsigned char *master_key);

#endif
