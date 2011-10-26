#! /bin/sh

# Copyright (C) 2001-2007 Peter Selinger.
# This file is part of Potrace. It is free software and it is covered
# by the GNU General Public License. See the file COPYING for details.

echo "Checking input formats..." >& 2

# we check that potrace can read different file formats without error,
# and produces identical output irrespective of the input file format.

if test -z "$srcdir"; then
    srcdir=.
fi

. "$srcdir/missing.sh"

NAME=`basename "$0"`

POTRACE="../src/potrace --progress"
TMPDIR="${TEMPDIR:-/tmp}"
TMP1=`mktemp "$TMPDIR/$NAME-1.XXXXXX"`
TMP2=`mktemp "$TMPDIR/$NAME-2.XXXXXX"`

action () {
    "$@"
    if test $? -ne 0; then
	echo "$NAME: test failed" >& 2
	echo "Failed command: $LINE: $@" >& 2
	exit 1
    fi
}

# keep track of line numbers
alias action="LINE=\$LINENO; action"

# available input files
INFILES="data1.pbm data1.pgm data1.ppm data1.bmp1 data1.bmp4 data1.bmp8 data1.bmp24 data1.bmp4r data1.bmp8r"

# extract first file
set dummy $INFILES; F="$2"

action $POTRACE -o "$TMP1" "$srcdir/$F"

for i in $INFILES; do
    action $POTRACE -o "$TMP2" "$srcdir/$i"
    action diff "$TMP1" "$TMP2" > /dev/null
    action rm -f "$TMP2"
done

action rm -f "$TMP1"

echo "$NAME: test succeeded" >& 2
exit 0
