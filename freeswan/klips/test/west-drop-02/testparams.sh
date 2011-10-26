#!/bin/sh

TESTNAME=west-drop-01
TESTHOST=west
EXITONEMPTY=--exitonempty
PRIVINPUT=../inputs/ikeinit-japan-sunrise.pcap
REFPUBOUTPUT=spi1-output.txt
REFCONSOLEOUTPUT=spi1-console.txt
REFCONSOLEFIXUPS="kern-list-fixups.sed nocr.sed"
REFCONSOLEFIXUPS="$REFCONSOLEFIXUPS klips-spi-sanitize.sed"
REFCONSOLEFIXUPS="$REFCONSOLEFIXUPS klips-debug-sanitize.sed"
REFCONSOLEFIXUPS="$REFCONSOLEFIXUPS ipsec-look-sanitize.sed"
TCPDUMPFLAGS="-n"
SCRIPT=spi1.sh



