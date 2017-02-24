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
    std::cout << std::hex << std::uppercase << std::setfill('0');
    // std::setw is not sticky, need to apply that to each byte
    for (auto & c : *h) {
        // cast to int required because uint8_t is an alias to unsigned char,
        // so std::cout would assume it's a character and print it out as such
        // (not taking std::hex into account)
        std::cout << std::setw(2) << static_cast<int>(c);
    }
    std::cout << std::dec << std::setfill(' ');
}
