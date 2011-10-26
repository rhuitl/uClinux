#!/usr/bin/perl
#
# very quick-and-dirty downscaler from 2^16 to 2^8 grey levels
# (because otherwise ppmtogif will complain "too many colours" and die)
#
# $Id: simplequant.pl,v 1.2 2001/11/20 20:48:14 gert Exp $
#
$format=<>;
chomp $format;
if ( $format ne 'P2' ) 
{
   die "$0: input format is '$format', not P2 (pgm)\n";
}

$_=<>;
chomp;
if ( $_ !~ /\d+\s\d+/ )
{
   die "$0: invalid x/y format: '$_'\n";
}

print "$format\n$_\n";

$samples=$1*$2;

$max=<>;
chomp $max;

if ( $max != 65535 && $max != 255 )
{
   die "$0: can only handle \$max values of 255 and 65535, not '$max'\n";
}

# new max: 255
print "255\n";

$scale = 255/$max;

while( <> )
{
   print join( " ", map $_ * $scale, split ),  "\n";
}
