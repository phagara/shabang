#include <iostream>
#include <boost/thread.hpp>
#include <boost/lockfree/spsc_queue.hpp>
#include "libbloom/bloom.h"
#include "sha_digest/sha256.h"
#include "datatypes.hpp"
#include "thread_hasher.hpp"


void thread_hasher(const Hash *seed, const size_t bitlen, struct bloom *bloom, DbReqQueue *dbq, HasherResQueue *resq) {
    // reusable SHA context
    SHA256_Context ctx;
    // previous & current hash value
    HashPair val;
    // seed becomes the previous "hash"
    val.first = *seed;
    // trim the seed
    trimHash(&val.first, bitlen);
    // counter of processed hashes
    ull hashes = 0;

    try {
        for (;;) {
            // compute hash of firsts bitlen bits of previous hash
            sha256_initialize(&ctx);
            sha256_add_bits(&ctx, &val.first[0], bitlen);
            sha256_calculate(&ctx, &val.second[0]);
            size_t len = trimHash(&val.second, bitlen);

            // if bloom filter (probably) contains the hash,
            // forward it to the db queue for confirmation
            if (bloom_check(bloom, &val.second[0], len)) {
                while (!dbq->push(HashPairDbReq(DBREQ_READ, val))) {
                    // iterruptible 1ms sleep if dbrq is full
                    boost::this_thread::sleep_for(boost::chrono::milliseconds(1));
                }
            }

            // submit to db queue
            while (!dbq->push(HashPairDbReq(DBREQ_WRITE, val))) {
                // iterruptible 1ms sleep if dbq is full
                boost::this_thread::sleep_for(boost::chrono::milliseconds(1));
            }

            // add the trimmed hash to the bloom filter
            bloom_add(bloom, &val.second[0], len);

            // current hash becomes preimage of the next one
            val.first = val.second;

            // increment the processed hash count
            hashes++;

            // give main thread a chance to stop us
            boost::this_thread::interruption_point();
        }
    } catch (boost::thread_interrupted) {
        // raised when we get interrupted
        // just push the processed hash count to the thread's result queue
        // (the busy wait here shouldn't be an issue)
        while (!resq->push(hashes));

        // ...and exit
        return;
    }
}
