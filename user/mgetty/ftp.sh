#!/bin/sh
#
VS="$1" ; HOST=$2 ; DIR=$3

if [ -z "$VS" -o -z "$HOST" -o -z "$DIR" ] ; then
    echo "Syntax error: $0 <VS> <HOST> <DIR>" >&2 ; exit 1
fi

SRC=mgetty$VS.tar.gz
if [ ! -f "$SRC" ] ; then
    echo "$0: can't find $SRC!" >&2 ; exit 2
fi

if expr "$VS" : '[0-9].[13579]' >/dev/null ; then
    DST=mgetty$VS-`date +%b%d`.tar.gz
else
    DST=mgetty+sendfax-$VS.tar.gz
fi

scp $SRC $HOST:$DIR/$DST
scp $SRC.asc $HOST:$DIR/$DST.asc

# find diff's, if any...
DIFF=`ls -rt mgetty*-$VS.diff.gz 2>/dev/null |tail -1`
#test -n "$DIFF" && DIFF="put $DIFF"
test -n "$DIFF" && \
	scp $DIFF $HOST:$DIR/$DIFF

# normal FTP upload
#ftp -v $HOST <<EOF
#cd $DIR
#bin
#hash
#umask 022
#put $SRC $DST
#put $SRC.asc $DST.asc
#$DIFF
#quit
#EOF
