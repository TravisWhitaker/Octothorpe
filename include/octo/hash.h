// libocto Copyright (C) Travis Whitaker 2013-2014

#ifndef OCTO_HASH_H
#define OCTO_HASH_H

// libocto's dual key hash function:
void octo_hash(const uint8_t *input, size_t input_length, uint8_t *output, const uint8_t *master_key);

#endif
