Octothorpe
==========

Master(stable) branch status: [![Build Status](https://travis-ci.org/TravisWhitaker/Octothorpe.png)](https://travis-ci.org/TravisWhitaker/Octothorpe)

Rationale
---------
Most existing C data structure libraries suck, especially their hash tables. Lets have a look, shall we?

- Glib is bloated and causes inter-platform funkiness
- sglib is totally unreadable, has an inconsistent interface, and is a macro maze
- cbfalconer has licensing issues
- Google Sparse-Hash is OK but the interface requires the use of C++ constructs
- strmap is simple and the code is readable, but you can't use arbitrary types for the keys and values
- uthash is high-performance and has a good interface, but there are major disadvantages to a macro-based implementation

When non-wimps write programs in C (as they are wont to do), they roll their own data structures anyway. Trees, linked lists, graphs? Easy. Self-extending strings? Sheesh, maybe you should use a [good high-level language](http://www.haskell.org/haskellwiki/Haskell) instead. Stacks and queues? Child's play! Hash tables? Those can be a pain to implement every time. And that's a shame, because like most other data structures there are sweet, sweet implementation-specific optimizations to be had. Should your buckets be arrays or linked lists? Should you optimize for insert performance or lookup performance or overhead? During collision handling should more recently inserted items be given priority? Does your hash domain need to be uniform, or would you be better off with bumps in the distribution around clusters of common keys? Can you deal with platform-dependent overhead?

Octothorpe implements many different types of hash tables with different advantages and presents a consistent interface. It's a real library and not a macro hell. It presents a cryptographic-strength hash function (a variant of [SipHash](https://131002.net/siphash/)) with dual-keys. This is a critical feature that other libraries leave out. The hash exhibits totally different (but well-distributed) behavior depending on a 128-bit master key that's used in addition to your arbitrary-length key. If fault tolerance is important to your application, you can easily re-hash with a new master key in a hash flood DoS scenario.

"Octothorpe" is a name for the # character coined by Bell Labs engineer Lauren Asplund in 1968.
