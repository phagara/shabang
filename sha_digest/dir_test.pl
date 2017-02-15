#!/usr/bin/perl

#  This is a very simple test program for the different SHA implementations.
#  It expects a directory as name its only argument and then runs all SHA
#  implementations on the files in that directory, comparing the results
#  to those from the GNU coreutils (which, of course, must be installed).
#  It aborts with an error message ahould any differences in the results
#  be found.
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

die "Sole argument must be a directory\n"
	unless defined $ARGV[ 0 ] and -d $ARGV[ 0 ];
my $dir = $ARGV[ 0 ];
$dir =~ s/\/$//;

for my $m ( qw/ 1 224 256 384 512 / ) {
	my $m1 = './sha' . $m . '_digest';
	my $m2 = 'sha' . $m . 'sum';

	opendir my $d, "$dir"
		or die "Can't read $dir\n";

	while ( my $fn = readdir $d ) {
		next unless -f "$dir/$fn" and -r "$dir/$fn";

		$fn =~ s/\(/\\\(/g;
		$fn =~ s/\)/\\\)/g;

		open my $f, '-|', "$m1 '$dir/$fn'" or die "Can't run $m1\n";
		my $r1 = <$f>;
		chomp $r1;
		close $f;

		open $f, '-|', "$m2 '$dir/$fn'" or die "Can't run $m2\n";
		my $r2 = <$f>;
		chomp $r2;
		close $f;
		$r2 =~ s/ .*//;

		die "invalid hash with $m1 on $dir/$fn\n" unless $r1 eq $r2;
		print "$m1 $dir/$fn ok\n";
	}
	closedir $d;
}

print "No problems have been detected\n";
