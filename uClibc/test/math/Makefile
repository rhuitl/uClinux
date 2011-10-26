# uClibc math tests
# Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.

TESTS := basic-test rint tst-definitions test-fpucw
# test-double test-idouble
# test-float test-ifloat
# test-ldouble test-ildouble

include ../Test.mak

DODIFF_rint     := 1

EXTRA_CFLAGS    := -DNO_LONG_DOUBLE -fno-builtin
EXTRA_LDFLAGS   := -lm

PERL := /usr/bin/perl
ulps-file := $(firstword $(wildcard $(config-sysdirs:%=$(..)%/libm-test-ulps)))
libm-test.c: $(ulps-file) libm-test.inc gen-libm-test.pl
	$(Q)$(PERL) ./gen-libm-test.pl -u $< ./libm-test.inc -o "." 2>&1 > /dev/null
EXTRA_CLEAN := libm-test.c
$(TARGETS): libm-test.c
