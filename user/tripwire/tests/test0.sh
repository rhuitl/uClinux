#!/bin/sh

# $Id: test0.sh,v 1.5 1993/12/12 01:39:09 genek Exp $ 

SIGGEN=$1
TESTDIR=$2
TEMPFILE=$3
TEST0KEY=$4
ME=$0

cat << GHK
=== $ME: DESCRIPTION

    This shell script exercises all the signature routines included in
the Tripwire distribution.  This suite is run on a series of files
created by the authors of the signature routines.

GHK

echo "=== $ME: BEGIN ==="

./createfiles $TESTDIR
rm -rf $TESTDIR/CVS
$SIGGEN -h $TESTDIR/* > $TEMPFILE
diff $TEMPFILE $TEST0KEY 
if [ $? -eq 0 ] 
then
    touch OKSIGS && rm $TEMPFILE 
    echo "=== $ME: PASS ==="
    exit 0
else
    echo Signatures do not match!  File $TEMPFILE should match $TEST0KEY.  Aborting... 
    echo "=== $ME: FAIL ==="
    exit 1
fi

