#include <iostream>
#include <iomanip>
#include <boost/thread.hpp>
#include <boost/program_options.hpp>
#include <boost/exception/all.hpp>
#include <leveldb/db.h>
#include "libbloom/bloom.h"
#include "sha_digest/sha256.h"

#include "datatypes.hpp"
#include "main.hpp"
#include "thread_database.hpp"
#include "thread_hasher.hpp"


namespace po = boost::program_options;


po::variables_map parse_args(int ac, char** av) {
    po::options_description desc("Allowed options");
    desc.add_options()
        ("help", "produce help message")
        ("seed", po::value<std::string>()->default_value("foo bar moo rar baz fez kek ayy!"),
         "string to start hashing from")
        ("bitlen", po::value<size_t>()->default_value(32),
         "collision prefix bit length")
        ("batch-size", po::value<ull>()->default_value(1e4),
         "hasher thread batch size for DB operations")
        ("bloom-size", po::value<ull>()->default_value(1e7),
         "bloom filter size")
        ("bloom-prob", po::value<double>()->default_value(0.0001),
         "bloom filter false-positive probability")
    ;

    po::variables_map vm;
    po::store(po::parse_command_line(ac, av, desc), vm);
    po::notify(vm);

    if (vm.count("help")) {
        std::cout << desc << std::endl;
        BOOST_THROW_EXCEPTION(OptionParserError());
    }

    if (vm.count("bitlen")) {
        if (vm["bitlen"].as<size_t>() > 8 * SHA256_HASH_SIZE) {
            std::cout << "Prefix bit length cannot be longer than the whole hash size!" << std::endl;
            BOOST_THROW_EXCEPTION(OptionParserError());
        }
    }

    if (vm.count("batch-size")) {
        if (vm["batch-size"].as<ull>() < 1) {
            std::cout << "Batch size needs to be >0." << std::endl;
            BOOST_THROW_EXCEPTION(OptionParserError());
        }
    }

    if (vm.count("bloom-size")) {
        if (vm["bloom-size"].as<ull>() < 1) {
            std::cout << "Need to store at least one element lol." << std::endl;
            BOOST_THROW_EXCEPTION(OptionParserError());
        }
    }

    if (vm.count("bloom-prob")) {
        if (vm["bloom-prob"].as<double>() <= 0.0 || vm["bloom-prob"].as<double>() >= 1.0) {
            std::cout << "Probability needs to be >0 && <1." << std::endl;
            BOOST_THROW_EXCEPTION(OptionParserError());
        }
    }

    return vm;
}


int main(int ac, char** av) {
    po::variables_map vm;
    try {
        vm = parse_args(ac, av);
    } catch (OptionParserError) {
        return 1;
    }

    std::string seed = vm["seed"].as<std::string>();
    size_t bitlen = vm["bitlen"].as<size_t>();
    ull batch_size = vm["batch-size"].as<ull>();
    ull bloom_size = vm["bloom-size"].as<ull>();
    double bloom_prob = vm["bloom-prob"].as<double>();

    // queues
    DbReqQueue dbq(batch_size);
    HasherResQueue hresq(1);
    DbResQueue dbresq(1);

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
    boost::thread database(thread_database, db, &dbq, &dbresq);

    // bloom setup
    struct bloom bloom;
    std::cout << "Setting up bloom filter for up to " << bloom_size / 1e6 << "M elems @ " << bloom_prob <<  " FP probability." << std::endl;
    if (bloom_init(&bloom, bloom_size, bloom_prob)) {
        std::cout << "Failed to init bloom filter! Tried to allocate " << static_cast<double>(bloom.bytes) / 1024 / 1024 <<  " MB." << std::endl;
        bloom_print(&bloom);
        return 1;
    }
    std::cout << "Bloom filter using " << static_cast<double>(bloom.bytes) / 1024 / 1024 <<  " MB (" << bloom.bpe << " bits per element)." << std::endl;

    // seed setup
    Hash seed_hash;
    SHA256_Context ctx;
    sha256_initialize(&ctx);
    sha256_add_bytes(&ctx, seed.c_str(), seed.length());
    sha256_calculate(&ctx, &seed_hash[0]);
    trimHash(&seed_hash, bitlen);

    std::cout << "Starting hasher thread with first " << bitlen << " bits of seed hash" << std::endl << "\t";
    printHash(&seed_hash);
    std::cout << std::endl;

    // hasher thread
    boost::thread hasher(thread_hasher, &seed_hash, bitlen, &bloom, &dbq, &hresq);

    // wait for db to confirm a collision
    database.join();
    
    // print the collision
    DbRes result;
    while (!dbresq.pop(result));

    if (std::get<0>(result) == std::get<1>(result)) {
        std::cout << "Found a hash cycle!" << std::endl;
        std::cout << "\t";
        printHash(&std::get<0>(result));
        std::cout << std::endl;
    } else {
        std::cout << "Found collision!" << std::endl << "\t";
        printHash(&std::get<0>(result));
        std::cout << std::endl << "\t";
        printHash(&std::get<1>(result));
        std::cout << std::endl << "Both of those hash to the same value:" << std::endl << "\t";
        printHash(&std::get<2>(result));
        std::cout << std::endl << "DB confirmed collision in " << std::get<3>(result) << " queries." << std::endl;
    }

    // stop hasher thread
    std::cout << "Interrupting hasher thread..." << std::endl;
    hasher.interrupt();
    hasher.join();
    ull hashes;
    while (!hresq.pop(hashes));
    std::cout << "Hasher thread processed " << hashes << " hashes." << std::endl;

    // cleanup    
    bloom_free(&bloom);
    delete db;
    leveldb::DestroyDB("/tmp/shadb", options);

    return 0;
}
