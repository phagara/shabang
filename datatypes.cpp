#include <iostream>
#include <iomanip>
#include "datatypes.hpp"


size_t trimHash(Hash *h, size_t bitlen) {
    size_t len = (bitlen % 8) ? (bitlen / 8) + 1 : (bitlen / 8);

    if (bitlen % 8)
        h->at(len-1) = h->at(len-1) & (0xFF << (8 - (bitlen % 8)));

    for (size_t i = len; i < h->size(); i++)
        h->at(i) = 0x00;

    return len;
}


void printHash(Hash *h) {
    std::cout << std::hex << std::uppercase;
    for (HashIter it = h->begin(); it != h->end(); ++it) {
        std::cout << std::setw(2) << std::setfill('0') << (unsigned int) *it;
    }
    std::cout << std::dec << std::setw(0) << std::setfill(' ');
}
