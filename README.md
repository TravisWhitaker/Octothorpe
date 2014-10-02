Octothorpe
==========

Master(stable) branch status: [![Build Status](https://travis-ci.org/TravisWhitaker/Octothorpe.png)](https://travis-ci.org/TravisWhitaker/Octothorpe)

Rationale
---------

Octothorpe implements many different types of hash tables with different advantages and presents a consistent interface. It presents a cryptographic-strength hash function (a variant of [SipHash](https://131002.net/siphash/)) with dual-keys. The hash exhibits different (but well-distributed) behavior depending on a 128-bit master key that's used in addition to your arbitrary-length key. If fault tolerance is important to your application, you can easily re-hash with a new master key in a hash flood DoS scenario.

"Octothorpe" is a name for the # character coined by Bell Labs engineer Lauren Asplund in 1968.
