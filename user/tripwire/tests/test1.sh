#!/bin/sh

# $Id: test1.sh,v 1.12 1993/12/15 17:03:45 genek Exp $ 

HOSTNAME=hostname
# check to see if we ran from top-level makefile!
if [ $# -ne 2 ]
then 
   echo "Sorry!  You must run this test from the top-level Makefile!"
   exit 1
fi

HOSTNAME=$1
DIST=$2
ME=$0

cat << GHK
=== $ME: DESCRIPTION

    This shell script tests all the Tripwire signature routines.
Consequently, this test may take awhile to complete, because even the
slowest signature routines are exercised.  On a Sequent Symmetry
running 16 Mhz Intel 80386s, this test takes over five minutes to
complete.

    This same test using only the MD5 routines completes in less
than 30 seconds.

    This test suite will ascertain whether the byte-ordering and 
machine-dependent routines are working correctly.

GHK

echo "=== $ME: BEGIN ==="
echo ''

echo creating: ./tw.db_TEST.@
echo creating: ./@tw.config

HOST=`$HOSTNAME`
CURRPATH=`pwd`
CURRPATH=`echo $CURRPATH | sed s,/tests$,,`

sed s,/tmp/genek/$DIST,$CURRPATH, < ./tw.db_TEST > ./tw.db_TEST.@; 
sed s,/tmp/genek/$DIST,$CURRPATH, < ./tw.conf.test > ./@tw.config; 

../src/tripwire -loosedir -c ./@tw.config -d ./tw.db_TEST.@; 

echo "=== $ME: END ===" 
echo ''

echo Tripwire should have only reported: 
echo "    added:   $CURRPATH/tests/@tw.config" 
echo "             $CURRPATH/tests/tw.db_TEST.@... "
echo "             $CURRPATH/tests/OKEXER... "
echo "    changed: $CURRPATH/... (maybe some directory sizes...) "
echo "             ...and any other files you may have changed!"
echo ''
echo ''
echo removing: ./tests/tw.db_TEST.@
echo removing: @tw.config
rm ./tw.db_TEST.@
rm ./@tw.config
