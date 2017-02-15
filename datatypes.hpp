#ifndef __DATATYPES_HPP__
#define __DATATYPES_HPP__

#include <array>
#include <vector>
#include "sha_digest/sha256.h"

#define DBREQ_WRITE 0
#define DBREQ_READ 1


typedef std::array<unsigned char, SHA256_HASH_SIZE> Hash;
typedef std::array<unsigned char, SHA256_HASH_SIZE>::iterator HashIter;
typedef std::pair<Hash, Hash>  HashPair;
typedef std::pair<unsigned char, HashPair> HashPairDbReq;
typedef std::vector<HashPairDbReq> HashPairDbReqVect;
typedef std::vector<HashPairDbReq>::iterator HashPairDbReqVectIter;

size_t trimHash(Hash *h, size_t bitlen);
void printHash(Hash *h);

#endif // __DATATYPES_HPP__
