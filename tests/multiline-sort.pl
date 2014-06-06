#! /usr/bin/perl

# Sorts groups of lines that start with a space, without moving them
# past the nearest line that does not start with a space.

use warnings;
use strict;
my @buffer = ();
while (<STDIN>) {
    if (/^ /) {
        push(@buffer, $_);
    } else {
        print $_ foreach sort(@buffer);
        print $_;
        @buffer = ();
    }
}
print $_ foreach sort(@buffer);
