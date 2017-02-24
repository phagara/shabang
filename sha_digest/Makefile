#  Copyright (C) 2009 Jens Thoms Toerring <jt@toerring.de>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with fsc2.  If not, see <http://www.gnu.org/licenses/>.


sources     := sha1.c sha224.c sha256.c sha384.c sha512.c
objects     := $(sources:.c=.o)
headers     := $(sources:.c=.h) sha_digest.h sha_types.h


# Set compiler to be used, what to add to the compiler flags and
# the special flags needed to create a shared library

CC          := gcc
CFLAGS      += -W -Wall -Wextra -pedantic -O2 -I.
LFLAGS      := -shared -fpic

# Set the directories where to install the library, the executable
# and the header files

lib_dir     := /usr/local/lib
bin_dir     := /usr/local/bin
include_dir := /usr/local/include


all: sha_digest sha_bdigest sha_btest libsha_digest.so libsha_digest.a

sha_digest: sha_digest.c $(sources) $(headers)
	$(CC) $(CFLAGS) -o $@ $< $(sources)
	for f in $(sources:.c=_digest); do        \
		ln -f -s $@ $$f;                      \
    done

sha_bdigest: sha_bdigest.c $(sources) $(headers)
	$(CC) $(CFLAGS) -o $@ $< $(sources)
	for f in $(sources:.c=_bdigest); do       \
		ln -f -s $@ $$f;                      \
    done

sha_btest: sha_btest.c $(sources) $(headers)
	$(CC) $(CFLAGS) -o $@ $< $(sources)
	for f in $(sources:.c=_btest); do         \
		ln -f -s $@ $$f;                      \
    done

libsha_digest.so: $(objects) $(headers)
	$(CC) $(CFLAGS) $(LFLAGS) $(objects) -o $@

libsha_digest.a: $(objects)
	ar rcs $@ $^

%.o: %.c %.h
	$(CC) $(CFLAGS) $(LFLAGS) -c -o $@ $<


test:
	for m in ShortMsg LongMsg Monte; do                                       \
		for i in 1 224 256 256 384 512; do                                    \
			echo "Running tests from 'shabytetestvectors/SHA$$i$$m.txt'";     \
			./nist_byte_test.pl "shabytetestvectors/SHA$$i$$m.txt" || exit 2; \
		done;                                                                 \
	done
	for m in ShortMsg LongMsg Monte; do                                       \
		for i in 1 224 256 256 384 512; do                                    \
			echo "Running tests from 'shabittestvectors/SHA$$i$$m.txt'";      \
			./nist_bit_test.pl "shabittestvectors/SHA$$i$$m.txt" || exit 2;   \
		done;                                                                 \
	done


install:
	install libsha_digest.so $(lib_dir)
	install sha_digest $(bin_dir)
	for f in $(sources:.c=_digest); do                  \
		ln -f -s $(bin_dir)/sha_digest $(bin_dir)/$$f;  \
    done
	install $(headers) $(include_dir)


uninstall:
	rm -f $(lib_dir)/libsha_digest.so
	rm -f $(addprefix $(bin_dir)/,$(sources:.c=_digest))
	rm -f $(bin_dir)/sha_digest
	rm -f $(addprefix $(include_dir)/,$(headers))

clean:
	rm -f $(objects) sha_digest sha_bdigest sha_btest libsha_digest.so libsha_digest.a \
		  $(sources:.c=_digest) $(sources:.c=_bdigest) $(sources:.c=_btest)  \
	      *~ */*~ .*~
