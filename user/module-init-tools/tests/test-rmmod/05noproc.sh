#! /bin/sh

MODTEST_OVERRIDE1=/proc/modules
MODTEST_OVERRIDE_WITH1=tests/tmp/modules
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

# We allow this in case proc is not mounted.
[ "`rmmod foo_bar`" = "DELETE_MODULE: foo_bar EXCL NONBLOCK " ]

# We don't allow any other errors.  Doesn't work if we're root.
if [ `id -u` -ne 0 ]; then
    touch tests/tmp/modules
    chmod 000 tests/tmp/modules

    [ "`rmmod foo_bar 2>&1`" = "FATAL: can't open /proc/modules: Permission denied" ]

    # But -f doesn't care
    [ "`rmmod -f foo_bar`" = "DELETE_MODULE: foo_bar EXCL TRUNC NONBLOCK " ]
fi
