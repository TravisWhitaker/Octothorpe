// libocto Copyright (C) Travis Whitaker 2013-2014

#include <stdio.h>
#include <string.h>

#include <octo/types.h>
#include <octo/hash.h>

#define rotate_left(x, y) (uint64_t)(((x) << (y)) | ((x) >> (64 - (y))))

#define uint32_to_uint8(a, b) (a)[0] = (uint8_t)((b)); (a)[1] = (uint8_t)((b) >> 8); (a)[2] = (uint8_t)((b) >> 16); (a)[3] = (uint8_t)((b) >> 24);

#define uint64_to_uint8(a, b) uint32_to_uint8((a), (uint32_t)((b))); uint32_to_uint8((a) + 4, (uint32_t)((b) >> 32));

#define uint8_to_uint64(a) \
(((uint64_t)((a)[0])) | \
((uint64_t)((a)[1]) << 8) | \
((uint64_t)((a)[2]) << 16) | \
((uint64_t)((a)[3]) << 24) | \
((uint64_t)((a)[4]) << 32) | \
((uint64_t)((a)[5]) << 40) | \
((uint64_t)((a)[6]) << 48) | \
((uint64_t)((a)[7]) << 56))

#define OCTOTHORPE \
do { \
	stat_0 += stat_1; stat_1=rotate_left(stat_1, 13); stat_1 ^= stat_0; stat_0=rotate_left(stat_0, 32); \
	stat_2 += stat_3; stat_3=rotate_left(stat_3, 16); stat_3 ^= stat_2; \
	stat_0 += stat_3; stat_3=rotate_left(stat_3, 21); stat_3 ^= stat_0; \
	stat_2 += stat_1; stat_1=rotate_left(stat_1, 17); stat_1 ^= stat_2; stat_2=rotate_left(stat_2, 32); \
} while(0)

// Given an arbitrary number input_length of bytes *input, give a 64-bit hash *output:
void octo_hash(const uint8_t *input, size_t input_length, uint8_t *output, const uint8_t *key)
{
	uint64_t stat_0 = 0x736f6d6570736575ULL;
	uint64_t stat_1 = 0x646f72616e646f6dULL;
	uint64_t stat_2 = 0x6c7967656e657261ULL;
	uint64_t stat_3 = 0x7465646279746573ULL;
	uint64_t b;
	uint64_t k0 = uint8_to_uint64(key);
	uint64_t k1 = uint8_to_uint64(key + 8);
	uint64_t m;
	const uint8_t *end = input + input_length - (input_length % sizeof(uint64_t));
	const int left = input_length & 7;
	b = ((uint64_t)input_length) << 56;
	stat_3 ^= k1;
	stat_2 ^= k0;
	stat_1 ^= k1;
	stat_0 ^= k0;
	for (;input != end; input += 8)
	{
		m = uint8_to_uint64(input);
		stat_3 ^= m;
		OCTOTHORPE;
		OCTOTHORPE;
		stat_0 ^= m;
	}
	switch(left)
	{
	case 7:
		b |= ((uint64_t)input[6]) << 48;
	case 6:
		b |= ((uint64_t)input[5]) << 40;
	case 5:
		b |= ((uint64_t)input[4]) << 32;
	case 4:
		b |= ((uint64_t)input[3]) << 24;
	case 3:
		b |= ((uint64_t)input[2]) << 16;
	case 2:
		b |= ((uint64_t)input[1]) <<  8;
	case 1:
		b |= ((uint64_t)input[0]);
		break;
	case 0:
		break;
	}
	stat_3 ^= b;
	OCTOTHORPE;
	OCTOTHORPE;
	stat_0 ^= b;
	stat_2 ^= 0xff;
	OCTOTHORPE;
	OCTOTHORPE;
	OCTOTHORPE;
	OCTOTHORPE;
	b = stat_0 ^ stat_1 ^ stat_2  ^ stat_3;
	uint64_to_uint8(output, b);
	return;
}
