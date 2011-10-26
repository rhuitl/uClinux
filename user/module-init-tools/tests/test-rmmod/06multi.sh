#! /bin/sh

MODTEST_OVERRIDE1=/proc/modules
MODTEST_OVERRIDE_WITH1=tests/tmp/modules
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

# Old style
echo 'foo 100 0' > tests/tmp/modules
echo 'bar 100 0' >> tests/tmp/modules

[ "`rmmod foo bar`" = "DELETE_MODULE: foo EXCL NONBLOCK 
DELETE_MODULE: bar EXCL NONBLOCK " ]

[ "`rmmod -f foo bar`" = "DELETE_MODULE: foo EXCL TRUNC NONBLOCK 
DELETE_MODULE: bar EXCL TRUNC NONBLOCK " ]

[ "`rmmod -w foo bar`" = "DELETE_MODULE: foo EXCL 
DELETE_MODULE: bar EXCL " ]

# First examine stdout (mixing them gives unpredictable results)
[ "`rmmod foo bar baz 2>/dev/null`" = "DELETE_MODULE: foo EXCL NONBLOCK 
DELETE_MODULE: bar EXCL NONBLOCK " ]
[ "`rmmod baz foo bar 2>/dev/null`" = "DELETE_MODULE: foo EXCL NONBLOCK 
DELETE_MODULE: bar EXCL NONBLOCK " ]

# Now examine stderr.
[ "`rmmod foo bar baz 2>&1 >/dev/null`" = "ERROR: Module baz does not exist in /proc/modules" ]
[ "`rmmod baz foo bar 2>&1 >/dev/null`" = "ERROR: Module baz does not exist in /proc/modules" ]
