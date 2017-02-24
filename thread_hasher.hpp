#ifndef SHABANG_THREAD_HASHER_HPP_
#define SHABANG_THREAD_HASHER_HPP_

#include <boost/lockfree/spsc_queue.hpp>
#include "libbloom/bloom.h"
#include "sha_digest/sha256.h"
#include "datatypes.hpp"


/*
 * Computes (trimmed) hashes, locally checks for possible collisions (via
 * a bloom filter), forwards all computed hashes and possible collisions
 * to DB thread for writing and confirmation, respectively.
 */
void thread_hasher(const Hash *seed, const size_t bitlen, struct bloom *bloom, DbReqQueue *dbq, HasherResQueue *resq);

#endif // SHABANG_THREAD_HASHER_HPP_
