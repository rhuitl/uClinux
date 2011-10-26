#!/usr/bin/perl

# escape.pl
# crude hack to generate a a packed bitmap of characters that
# need escaping for HTTP protocol.  See RFC-1738 Section 2.2.

# Copyright 1998 Larry Doolittle   <ldoolitt@jlab.org>
# tested standalone Jan 4, 1998
# inserted into Boa Jan 11, 1998

# designed for cache-friendliness, and 32-bit machines.
# someone with an Alpha is welcome to submit a revised
# version that autodetects word size.

# usage:
# escape.pl >escape.h
# (above can be a dependency in the makefile, but ship with
# a working escape.h in case someone doesn't happen to have perl
# around). 

# and in the C code:
#    unsigned long _needs_escape[8] = {
#  #include "escape.h"
#    };
#  #define needs_escape(c) (_needs_escape[(c)>>5]&(1<<((c)&0x1f)))

for $i (0..7) {$word[$i]=0xffffffff;}
for $c ("!", "(", ")", "*", "+", ",", "-", ".", "/",
        "0".."9", ":", "?", "A".."Z", "_",  "a".."z", "~") {
   $i=unpack("C",$c);
   # printf "%s %d\n",$c,$i;}
   $word[$i>>5]&=~(1<<($i&0x1f));
}
$delim = " ";
printf "#ifndef __NEEDS_ESCAPE__\n";
printf "#define __NEEDS_ESCAPE__\n";
printf "unsigned long _needs_escape[8] = {\n";
for $i (0..7) {printf "%s 0x%x", $delim, $word[$i]; $delim=","}
printf "\n };\n#define needs_escape(c) ";
printf "(_needs_escape[(c)>>5]&(1<<((c)&0x1f)))\n";
print "#endif\n"; 


