#!/bin/sh

TESTHOST=east
TESTNAME=east-icmp-01
EXITONEMPTY=--exitonempty
SCRIPT=setkey.sh
REFCONSOLEOUTPUT=parityerror.txt
REFCONSOLEFIXUPS="kern-list-fixups.sed nocr.sed"
