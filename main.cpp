#include <iostream>
#include <iomanip>
#include <boost/thread.hpp>
#include <boost/program_options.hpp>
#include <leveldb/db.h>
#include "libbloom/bloom.h"
#include "sha_digest/sha256.h"

#include "datatypes.hpp"
#include "thread_database.hpp"
#include "thread_hasher.hpp"


namespace po = boost::program_options;


int main(int ac, char** av) {
    unsigned int bitlen = 32;
    unsigned long long bloom_elems = 1e8;
    double bloom_prob = 0.0001;

    po::options_description desc("Allowed options");
    desc.add_options()
        ("help", "produce help message")
        ("bitlen", po::value<unsigned int>(), "set collision prefix bit length (default: 32)")
        ("bloom-size", po::value<unsigned long long>(), "set bloom filter size (default: 100M)")
        ("bloom-prob", po::value<double>(), "set bloom filter false-positive probability (default: 0.0001)")
    ;

    po::variables_map vm;
    po::store(po::parse_command_line(ac, av, desc), vm);
    po::notify(vm);

    if (vm.count("help")) {
        std::cout << desc << std::endl;
        return 1;
    }

    if (vm.count("bitlen")) {
        bitlen = vm["bitlen"].as<unsigned int>();
        if (bitlen > 8 * SHA256_HASH_SIZE) {
            std::cout << "Prefix bit length cannot be longer than the whole hash size!" << std::endl;
            return 1;
        }
    }

    if (vm.count("bloom-size")) {
        bloom_elems = vm["bloom-size"].as<unsigned long long>();
        if (bloom_elems <= 1) {
            std::cout << "Need to store at least one element lol." << std::endl;
            return 1;
        }
    }

    if (vm.count("bloom-prob")) {
        bloom_prob = vm["bloom-prob"].as<double>();
        if (bloom_prob <= 0 || bloom_prob >= 1) {
            std::cout << "Probability needs to be >0 && <1." << std::endl;
            return 1;
        }
    }

    // queues
    boost::lockfree::spsc_queue<HashPairDbReq> dbq(10240);
    boost::lockfree::spsc_queue<unsigned long long> hasher_resq(1);
    boost::lockfree::spsc_queue<std::pair<HashPair, unsigned long long> > database_resq(1);

    // db setup
    leveldb::DB* db;
    leveldb::Options options;
    options.create_if_missing = true;
    options.error_if_exists = true;
    leveldb::Status status = leveldb::DB::Open(options, "/tmp/shadb", &db);
    if (!status.ok()) {
        std::cout << "Failed to create LevelDB!" << std::endl;
        return 1;
    }

    // db thread
    boost::exception_ptr err;
    boost::thread database(thread_database, db, &dbq, &database_resq, err);

    // bloom setup
    struct bloom bloom;
    std::cout << "Setting up bloom filter for up to " << bloom_elems / 1e6 << "M elems @ " << bloom_prob <<  " FP probability." << std::endl;
    if (bloom_init(&bloom, bloom_elems, bloom_prob)) {
        std::cout << "Failed to init bloom filter! Tried to allocate " << (double) bloom.bytes / 1024 / 1024 <<  " MB." << std::endl;
        bloom_print(&bloom);
        return 1;
    }
    std::cout << "Bloom filter using " << (double) bloom.bytes / 1024 / 1024 <<  " MB (" << bloom.bpe << " bits per element)." << std::endl;

    // seed setup
    Hash seed { {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
    } };

    std::cout << "Starting hasher thread with seed ";
    printHash(&seed);
    std::cout << " and bit length " << bitlen << "." << std::endl;

    // hasher thread
    boost::thread hasher(thread_hasher, &seed, bitlen, &bloom, &dbq, &hasher_resq);

    // wait for db to confirm a collision
    database.join();
    
    // print the collision
    std::pair<HashPair, unsigned long long> result;
    while (!database_resq.pop(result));

    if (result.first.first == result.first.second) {
        std::cout << "Found a hash cycle, not a collision. :(" << std::endl;
        std::cout << "\t";
        printHash(&result.first.first);
        std::cout << std::endl;
        std::cout << "Perhaps try a different seed." << std::endl;
    } else {
        std::cout << "Found collision!" << std::endl << "\t";
        printHash(&result.first.first);
        std::cout << std::endl << "\t";
        printHash(&result.first.second);
        std::cout << std::endl;
        std::cout << "DB confirmed collision in " << result.second << " queries." << std::endl;
    }

    // stop hasher thread
    std::cout << "Interrupting hasher thread..." << std::endl;
    hasher.interrupt();
    hasher.join();
    unsigned long long hashes;
    while (!hasher_resq.pop(hashes));
    std::cout << "Hasher thread processed " << hashes << " hashes." << std::endl;

    // cleanup    
    bloom_free(&bloom);
    delete db;
    leveldb::DestroyDB("/tmp/shadb", options);

    return 0;
}
