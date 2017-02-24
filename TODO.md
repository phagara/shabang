* convert `Hash` into a class that remembers the prefix bit length and can be passed directly to `std::cout` instead of having to use the `printHash` function (printing only the first `bitlen` bits rounded up to whole bytes)
* add progress indication (live hasher thread computed hash count & db read query count)
* auto-remove the temporary LevelDB database directory on abnormal program termination (^C or other exception)
* add checkpointing to allow resuming collision search after interrupting the program
* test that boost exceptions thrown from a thread end up in the main process
* better handling of found hash cycles
* wrap leveldb in a shadb-specific class (HashDb?)
* measure performance of threads, queue wait, time spent hashing/writing DB/reading DB, etc...
