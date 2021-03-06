#include <iostream>
#include <iterator>
#include <boost/thread.hpp>
#include <boost/exception/all.hpp>
#include <leveldb/db.h>
#include <leveldb/write_batch.h>
#include "datatypes.hpp"
#include "thread_database.hpp"


void thread_database(leveldb::DB *db, DbReqQueue *dbq, DbResQueue *resq) {
    // number of database read requests needed to confirm a collision (>=1)
    ull dbqueries = 0;
    // local storage of read/write requests
    HashPairDbReqVect pairs;
    // helper variable
    std::string value;
    bool empty_batch;

    for (;;) {
        // try to consume requests from dbwq
        if (dbq->pop(std::back_inserter(pairs))) {
            // we got some requests! process all writes up to a (possible) read
            leveldb::WriteBatch batch;
            empty_batch = true;
            for (auto & pair : pairs) {
                // have to convert Hash type (char vector) to leveldb's Slice
                // as it only accepts that or an std::string
                if (pair.first == DBREQ_WRITE) {
                    // write req, just add to write batch
                    empty_batch = false;
                    batch.Put(
                            leveldb::Slice(
                                reinterpret_cast<char*>(&pair.second.second[0]),
                                pair.second.second.size()),
                            leveldb::Slice(
                                reinterpret_cast<char*>(&pair.second.first[0]),
                                pair.second.first.size()));
                } else if (pair.first == DBREQ_READ) {
                    // read req -- need to flush all preceding writes first!
                    if (!empty_batch) {
                        leveldb::Status s = db->Write(leveldb::WriteOptions(), &batch);
                        if (!s.ok()) {
                            // write failed, raise an exception
                            BOOST_THROW_EXCEPTION(LevelDbWriteError());
                        }
                        // clear the batch so we can continue processing more writes
                        batch.Clear();
                        empty_batch = true;
                    }

                    // writes done, start the search
                    dbqueries++;
                    leveldb::Status s = db->Get(
                            leveldb::ReadOptions(),
                            leveldb::Slice(
                                reinterpret_cast<char*>(&pair.second.second[0]),
                                pair.second.second.size()),
                            &value);

                    if (s.ok()) {
                        // found a match! convert the std::string to Hash
                        Hash preimage;
                        std::copy(value.begin(), value.end(), preimage.begin());

                        // if preiamge == it->second.first, then we found a hash cycle without getting a collision
                        // need to check for that in the main thread, nothing we can do about it here :(

                        // if we got all the way here, the collision is confirmed, write it to
                        // the thread's result queue (busy wait shouldn't be an issue here)
                        while (!resq->push(DbRes(preimage, pair.second.first, pair.second.second, dbqueries)));
                        // and exit
                        return;
                    } else if (!s.IsNotFound()) {
                        // status was not OK and it wasn't just a NotFound error!
                        // something went wrong (DB corruption or w/e) -- throw an exc
                        BOOST_THROW_EXCEPTION(LevelDbReadError());
                    }
                } else {
                    BOOST_THROW_EXCEPTION(InvalidDbOperation());
                }
            }

            // save the rest
            if (!empty_batch) {
                leveldb::Status s = db->Write(leveldb::WriteOptions(), &batch);
                if (!s.ok()) {
                    // write failed, raise an exception
                    BOOST_THROW_EXCEPTION(LevelDbWriteError());
                }
            }

            // all writes & reads processed
            pairs.clear();

            // give the main process a change to interrupt us
            boost::this_thread::interruption_point();
        } else {
            // DB thread starvation -- not sure how this is possible
            boost::this_thread::sleep_for(boost::chrono::milliseconds(1));
        }
    }
}
