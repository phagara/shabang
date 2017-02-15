#!/usr/bin/perl

#  This script allows to test the SHA implementations using the test
#  vectors distributed by the NIST, see
#
#  http://csrc.nist.gov/groups/STM/cavp/index.html
#  http://csrc.nist.gov/groups/STM/cavp/documents/shs/SHAVS.pdf
#  http://csrc.nist.gov/groups/STM/cavp/documents/shs/shabytetestvectors.zip
#
#  It expects a single argument, the name of the test vector file, which
#  are 
#
#   SHA1ShortMsg.txt     SHA1LongMsg.txt     SHA1Monte.txt
#   SHA224ShortMsg.txt   SHA224LongMsg.txt   SHA224Monte.txt
#   SHA256ShortMsg.txt   SHA256LongMsg.txt   SHA256Monte.txt
#   SHA384ShortMsg.txt   SHA384LongMsg.txt   SHA384Monte.txt
#   SHA512ShortMsg.txt   SHA512LongMsg.txt   SHA512Monte.txt
#
#  and runs the required tests on them. Please note that the tests may
#  run for quite a long time, especially the Monte-Carlo tests (each
#  one requires 100,000 hash digest calculations)!
#
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


use strict;
use warnings;
use IPC::Open2;


die "Missing file\n" unless defined $ARGV[ 0 ];

die "Input file '$ARGV[ 0 ]' doesn't exist\n" unless -e $ARGV[ 0 ];

die "Can't open input file '$ARGV[ 0 ]' for reading\n" unless -r $ARGV[ 0 ];

die "Invalid input file '$ARGV[ 0 ]'\n"
	unless $ARGV[ 0 ] =~ /(^|\/)SHA(1|(224)|(256)|(384)|(512))((((Short)|(Long))Msg)|(Monte))\.txt$/;

my ( $alg, $type ) = ( $2, $7 );

if ( $type eq 'LongMsg' || $type eq 'ShortMsg' ) {
    open my $in, '<', $ARGV[ 0 ]
		or die "Failed to open input file '$ARGV[ 0 ]'\n";

	while ( 1 ) {
		my $line;
		my $len;
		while ( $line = <$in> ) {
			next unless $line =~ /^Len\s+=\s+(\d+)\s*$/;
			$len = $1;

			my $msg = <$in>;
			$msg =~ s/^Msg\s+=\s+([a-f0-9]+)\s*$/$1/;

			my $digest = <$in>;
			$digest =~ s/^MD\s+=\s+([a-f0-9]+)\s*$/$1/;
			<$in>;

			my $pack_format = 'H' . length $msg;
			my $pid = open2 my $from, my $to, "./sha$alg\_digest";
			print $to pack $pack_format, $msg if $len > 0;
			close $to;

			my $res = <$from>;
			close $from;
			waitpid $pid, 0;

			chomp $res;
			if ( $res eq $digest ) {
				print "sha$alg\_digest: Ok for LEN = $len\n";
			} else {
				die "sha$alg\_digest: Failure for LEN = $len\n";
			}
		}

		last;
	}

	close $in;
} else {
    open my $in, '<', $ARGV[ 0 ]
		or die "Failed to open input file '$ARGV[ 0 ]'\n";

	my $seed;

	my $line;
	while ( $line = <$in> ) {
		next unless $line =~ /^Seed\s+=\s+([a-z0-9]+)\s*$/;
		$seed = $1;
		$line = <$in>;
		last;
	}

	my @stages;

	while ( 1 ) {
		while ( $line = <$in> ) {
			die "Invalid input at line $.\n"
				unless $line =~ /^COUNT\s+=\s+(\d+).*$/;

			$line = <$in>;
			die "Invalid input at line $.\n"
			   unless $line =~ s/^MD\s+=\s+([a-f0-9]+)\s*$/$1/;
			push @stages, $1;
			$line = <$in>
		}

		last;
	}
	close $in;

	my $count = 0;
	my $pack_format = 'H' . ( 3 * length $seed );
	my @mod = ( $seed, $seed, $seed );

	for my $stage ( @stages ) {
		for my $j ( 0 ... 999 ) {
			my $pid = open2 my $from, my $to, "./sha$alg\_digest";
			print $to pack $pack_format, $mod[ 0 ] . $mod[ 1 ] . $mod[ 2 ];
			close $to;

			$mod[ 3 ] = <$from>;
			close $from;
			chomp $mod[ 3 ];

			waitpid $pid, 0;

			shift @mod;
		}

		if ( $stage eq $mod[ 2 ] ) {
			print "sha$alg\_digest: Ok COUNT = $count\n";
		} else {
			die "sha$alg\_digest: Failure for COUNT = $count\n"
		}
		$count++;
		@mod = ( $mod[ 2 ], $mod[ 2 ], $mod[ 2 ] );
	}
}
