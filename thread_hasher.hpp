#ifndef __THREAD_HASHER_HPP__
#define __THREAD_HASHER_HPP__

#include <boost/lockfree/spsc_queue.hpp>
#include "libbloom/bloom.h"
#include "sha_digest/sha256.h"
#include "datatypes.hpp"


/*
 * Computes (trimmed) hashes, locally checks for possible collisions (via
 * a bloom filter), forwards all computed hashes and possible collisions
 * to DB thread for writing and confirmation, respectively.
 */
void thread_hasher(const Hash *seed, const size_t bitlen, struct bloom *bloom,
        boost::lockfree::spsc_queue<HashPairDbReq> *dbq,
        boost::lockfree::spsc_queue<unsigned long long> *resq);

#endif //__THREAD_HASHER_HPP__
