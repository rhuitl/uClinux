#! /bin/sh

MODTEST_OVERRIDE1=/proc/modules
MODTEST_OVERRIDE_WITH1=tests/tmp/modules

# Old style
echo 'foo_bar 100 0' > tests/tmp/modules

[ "`rmmod -f foo_bar`" = "DELETE_MODULE: foo_bar EXCL TRUNC NONBLOCK " ]
[ "`rmmod -f foo-bar`" = "DELETE_MODULE: foo_bar EXCL TRUNC NONBLOCK " ]

[ "`rmmod -f /lib/modules/2.5.52/kernel/foo_bar.o`" = "DELETE_MODULE: foo_bar EXCL TRUNC NONBLOCK " ]
[ "`rmmod -f /lib/modules/2.5.52/kernel/foo_bar.ko`" = "DELETE_MODULE: foo_bar EXCL TRUNC NONBLOCK " ]
[ "`rmmod -f /lib/modules/2.5.52/kernel/foo-bar.ko`" = "DELETE_MODULE: foo_bar EXCL TRUNC NONBLOCK " ]

[ "`rmmod -w foo_bar`" = "DELETE_MODULE: foo_bar EXCL " ]
[ "`rmmod -w foo-bar`" = "DELETE_MODULE: foo_bar EXCL " ]

[ "`rmmod -w /lib/modules/2.5.52/kernel/foo_bar.o`" = "DELETE_MODULE: foo_bar EXCL " ]
[ "`rmmod -w /lib/modules/2.5.52/kernel/foo_bar.ko`" = "DELETE_MODULE: foo_bar EXCL " ]
[ "`rmmod -w /lib/modules/2.5.52/kernel/foo-bar.ko`" = "DELETE_MODULE: foo_bar EXCL " ]

# Both should work on "in-use" modules.
echo 'foo_bar 100 1' > tests/tmp/modules

[ "`rmmod -f foo_bar`" = "DELETE_MODULE: foo_bar EXCL TRUNC NONBLOCK " ]
[ "`rmmod -w foo_bar`" = "DELETE_MODULE: foo_bar EXCL " ]
