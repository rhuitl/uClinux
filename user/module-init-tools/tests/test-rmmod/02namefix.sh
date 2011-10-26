#! /bin/sh

MODTEST_OVERRIDE1=/proc/modules
MODTEST_OVERRIDE_WITH1=tests/tmp/modules
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

# Old style
echo 'foo_bar 100 0' > tests/tmp/modules

[ "`rmmod foo_bar`" = "DELETE_MODULE: foo_bar EXCL NONBLOCK " ]

[ "`rmmod /lib/modules/2.5.52/kernel/foo_bar.o`" = "DELETE_MODULE: foo_bar EXCL NONBLOCK " ]

[ "`rmmod /lib/modules/2.5.52/kernel/foo_bar.ko`" = "DELETE_MODULE: foo_bar EXCL NONBLOCK " ]

[ "`rmmod /lib/modules/2.5.52/kernel/foo-bar.ko`" = "DELETE_MODULE: foo_bar EXCL NONBLOCK " ]

[ "`rmmod foo-bar`" = "DELETE_MODULE: foo_bar EXCL NONBLOCK " ]
