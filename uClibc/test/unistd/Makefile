# uClibc unistd tests
# Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.

include ../Test.mak

OPTS_getopt      := -abcXXX -9
OPTS_getopt_long := --add XXX --delete YYY --verbose
ifeq ($(UCLIBC_HAS_GNU_GETOPT),y)
OPTS_tstgetopt   := -a -b -cfoobar --required foobar --optional=bazbug --none random --col --color --colour
else
# reordering is not supported, behaves as if POSIXLY_CORRECT would be set
OPTS_tstgetopt   := -a -b -cfoobar --required foobar --optional=bazbug --none --colou --color --colour random
endif
