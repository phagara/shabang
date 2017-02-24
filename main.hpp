#ifndef SHABANG_MAIN_HPP_
#define SHABANG_MAIN_HPP_

#include <boost/program_options.hpp>
#include <boost/exception/all.hpp>


struct OptionParserError : public boost::exception, public std::runtime_error {
    OptionParserError()
    : std::runtime_error("User supplied a bad value for a parameter.")
    {}
};


boost::program_options::variables_map parse_args(int ac, char** av);

#endif // SHABANG_MAIN_HPP_
