Hash Table Implementation Strategies
====================================

Chained Array(carry)
--------------------
In chained array tables, the hash function is used to index against a list of buckets, where each bucket consists of a 2 byte header followed by an array of variable length in an independently allocated heap block. The first byte of the header indicates the number of records in the bucket, while the second byte indicates the number of records that would fit in the bucket at its current size.

	┌───────────────────┐
	│ octo_dict_carry_t │
	├───────────────────┤
	│        x0*        │
	├───────────────────┤
	│        x1*        │
	├───────────────────┤
	│        ...        │
	├───────────────────┤
	│        xn*        │
	└───────────────────┘
