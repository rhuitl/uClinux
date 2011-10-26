#! /bin/sh

MODTEST_OVERRIDE1=/proc/modules
MODTEST_OVERRIDE_WITH1=tests/tmp/modules
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

# Old style
echo 'foo_bar 100 1' > tests/tmp/modules

[ "`rmmod foo_bar 2>&1`" = "ERROR: Module foo_bar is in use" ]
[ "`rmmod foo-bar 2>&1`" = "ERROR: Module foo_bar is in use" ]

# Old style with dependencies
echo 'foo_bar 100 1 dep1' > tests/tmp/modules

[ "`rmmod foo_bar 2>&1`" = "ERROR: Module foo_bar is in use by dep1" ]
[ "`rmmod foo-bar 2>&1`" = "ERROR: Module foo_bar is in use by dep1" ]

echo 'foo_bar 100 1 dep1 dep2' > tests/tmp/modules

[ "`rmmod foo_bar 2>&1`" = "ERROR: Module foo_bar is in use by dep1 dep2" ]
[ "`rmmod foo-bar 2>&1`" = "ERROR: Module foo_bar is in use by dep1 dep2" ]

# New style
echo 'foo_bar 100 1 -' > tests/tmp/modules

[ "`rmmod foo_bar 2>&1`" = "ERROR: Module foo_bar is in use" ]
[ "`rmmod foo-bar 2>&1`" = "ERROR: Module foo_bar is in use" ]

echo 'foo_bar 100 1 a,' > tests/tmp/modules

[ "`rmmod foo_bar 2>&1`" = "ERROR: Module foo_bar is in use by a" ]
[ "`rmmod foo-bar 2>&1`" = "ERROR: Module foo_bar is in use by a" ]

echo 'foo_bar 100 1 a,b,' > tests/tmp/modules

[ "`rmmod foo_bar 2>&1`" = "ERROR: Module foo_bar is in use by a,b" ]
[ "`rmmod foo-bar 2>&1`" = "ERROR: Module foo_bar is in use by a,b" ]

echo 'foo_bar 100 1 a,b, newoption' > tests/tmp/modules

[ "`rmmod foo_bar 2>&1`" = "ERROR: Module foo_bar is in use by a,b" ]
[ "`rmmod foo-bar 2>&1`" = "ERROR: Module foo_bar is in use by a,b" ]

# Not in use (newstyle)
echo 'foo_bar 100 0 -' > tests/tmp/modules
[ "`rmmod foo_bar`" = "DELETE_MODULE: foo_bar EXCL NONBLOCK " ]
[ "`rmmod foo-bar`" = "DELETE_MODULE: foo_bar EXCL NONBLOCK " ]

echo 'foo_bar 100 0 - newoption' > tests/tmp/modules
[ "`rmmod foo_bar`" = "DELETE_MODULE: foo_bar EXCL NONBLOCK " ]
[ "`rmmod foo-bar`" = "DELETE_MODULE: foo_bar EXCL NONBLOCK " ]
