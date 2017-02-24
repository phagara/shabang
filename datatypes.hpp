#ifndef SHABANG_DATATYPES_HPP_
#define SHABANG_DATATYPES_HPP_

#include <array>
#include <vector>
#include <boost/lockfree/spsc_queue.hpp>
#include <boost/exception_ptr.hpp>
#include "sha_digest/sha256.h"


const uint8_t DBREQ_WRITE = 0;
const uint8_t DBREQ_READ = 1;

typedef unsigned long long ull;
typedef unsigned char uch;

typedef std::array<uch, SHA256_HASH_SIZE> Hash;
typedef std::pair<Hash, Hash>  HashPair;

typedef std::pair<uch, HashPair> HashPairDbReq;
typedef std::vector<HashPairDbReq> HashPairDbReqVect;
typedef boost::lockfree::spsc_queue<HashPairDbReq> DbReqQueue;

typedef boost::lockfree::spsc_queue<ull> HasherResQueue;

typedef std::tuple<Hash, Hash, Hash, ull> DbRes;
typedef boost::lockfree::spsc_queue<DbRes> DbResQueue;


size_t trimHash(Hash *h, size_t bitlen);
void printHash(Hash *h);

#endif // SHABANG_DATATYPES_HPP_
