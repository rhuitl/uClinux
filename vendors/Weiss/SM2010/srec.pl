#!/usr/bin/perl
#*****************************************************************************
#* 
#*  @file          srec.pl
#*
#*                 simple srec-hexfile generator for SM 2010
#*                 
#*                 The SM 2010 isn't compatible with srec-files genarated 
#*                 by some programs (like gnu objcopy)
#*
#*                 use this script to create a hex file from a binary file
#*                 which will hopefully work on the SM2010
#*                 
#*                 syntax:
#*                 perl srec.pl binfile >hexfile
#*
#*  @version       0.1.0
#*  @date          2001/07/16
#*  @author        Guido Classen
#* 
#*  @par Changes:
#*  
#*****************************************************************************

open binfile, '<', $ARGV[0] or die "Open input file\nsyntax: srec.pl binfile";
binmode binfile, ":raw";

print "S00600004844521B\n" ;

my $addr = 0xe00040;
my $reccount = 0;

while (read(binfile,$rline,16)>0) {
    my $checksum = unpack("%8C*", $rline);
    my $len = length($rline);
    $_ = unpack("H*", $rline);
    $_ =~ tr/a-z/A-Z/;    
    $checksum += $len + 4 + unpack("%8C*", pack("I", $addr));
    printf "S2%02X%06X%s%02X\n", $len+4, $addr, $_, 
        (0xff - $checksum) & 0xff;
    $addr += $len;
    $reccount++;
}

printf "S503%04X%02X\n", $reccount, 
    (0xff - (unpack("%8C*", pack("I", $reccount))+3)) & 0xff;
print "S804E00040DB\n"

