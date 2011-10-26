#!/bin/sh

TESTNAME=east-espiv-01
TEST_PURPOSE=exploit
TEST_EXPLOIT_URL="http://www.hut.fi/~svaarala/espiv.pdf"

TESTHOST=east
EXITONEMPTY=--exitonempty
PRIVINPUT=../inputs/01-sunrise-sunset-ping.pcap

REF_PUB_OUTPUT=spi1-output.txt
REF_PUB_FILTER=./examineIV.pl
REF_CONSOLE_OUTPUT=spi1-console.txt
REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REFCONSOLEFIXUPS klips-spi-sanitize.sed"
REF_CONSOLE_FIXUPS="$REFCONSOLEFIXUPS klips-debug-sanitize.sed"
REF_CONSOLE_FIXUPS="$REFCONSOLEFIXUPS ipsec-look-sanitize.sed"
TCPDUMPFLAGS="-n -x -X -s 1600"
SCRIPT=spi1.sh



