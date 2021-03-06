#ifndef SHABANG_THREAD_DATABASE_HPP_
#define SHABANG_THREAD_DATABASE_HPP_

#include <boost/exception_ptr.hpp>
#include <boost/exception/all.hpp>
#include <boost/lockfree/spsc_queue.hpp>
#include <leveldb/db.h>
#include "datatypes.hpp"


/*
 * Exception for when a write to LevelDB fails.
 */
struct LevelDbWriteError : public boost::exception, public std::runtime_error {
    LevelDbWriteError()
    : std::runtime_error("Writing a batch of hashes to LevelDB failed!")
    {}
};


/*
 * Exception for when a read from LevelDB fails.
 */
struct LevelDbReadError : public boost::exception, public std::runtime_error {
    LevelDbReadError()
    : std::runtime_error("Reading a hash from LevelDB failed!")
    {}
};


/*
 * Exception for when a DB request is invalid.
 */
struct InvalidDbOperation : public boost::exception, public std::runtime_error {
    InvalidDbOperation()
    : std::runtime_error("Invalid DB operation!")
    {}
};


/*
 * Consumes and processes write and read requests from hasher thread,
 * exits when a read request is confirmed as a hash collision.
 */
void thread_database(leveldb::DB *db, DbReqQueue *dbq, DbResQueue *resq);

#endif // SHABANG_THREAD_DATABASE_HPP_
