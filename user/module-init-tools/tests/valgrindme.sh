#! /bin/sh

# Make sure it finds real one this time.
PATH=`pwd`:$PATH
valgrind -q --num-callers=8 --suppressions=tests/vg-suppressions --log-fd=3 `basename $0` "$@" 3>/tmp/valgrind
ret=$?

if [ -s /tmp/valgrind ]; then
    echo VALGRIND FAILED for $0 "$@" > /proc/$PPID/fd/1
    cat /tmp/valgrind > /proc/$PPID/fd/1
    kill $PPID
    exit 1
fi
exit $ret
