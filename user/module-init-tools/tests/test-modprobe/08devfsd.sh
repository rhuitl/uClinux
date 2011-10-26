#! /bin/sh

# Old devfsds invoke "modprobe -k -C /etc/modules.conf /dev/<name>".
# We have a horrible workaround.

MODTEST_OVERRIDE1=/lib/modules/$MODTEST_UNAME/modules.dep
MODTEST_OVERRIDE_WITH1=/dev/null
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

MODTEST_OVERRIDE2=/etc/modprobe.conf
MODTEST_OVERRIDE_WITH2=/dev/null
export MODTEST_OVERRIDE2 MODTEST_OVERRIDE_WITH2

MODTEST_OVERRIDE3=/etc/modules.conf
MODTEST_OVERRIDE_WITH3=FILE-WHICH-DOESNT-EXIST
export MODTEST_OVERRIDE3 MODTEST_OVERRIDE_WITH3

# Ignores explicit -C when it's -C modules.conf, and a /dev/*.
[ "`modprobe -C /etc/modules.conf /dev/foo 2>&1`" = "" ]

# These won't trigger it.
[ "`modprobe -C /etc/modules.conf2 /dev/foo 2>&1`" = "FATAL: Failed to open config file /etc/modules.conf2: No such file or directory" ]
[ "`modprobe -C /etc/modules.conf x/dev/foo 2>&1`" = "FATAL: Failed to open config file /etc/modules.conf: No such file or directory" ]
[ "`modprobe -C /etc/modules.conf /devsomething 2>&1`" = "FATAL: Failed to open config file /etc/modules.conf: No such file or directory" ]
[ "`modprobe /dev/foo 2>&1`" = "FATAL: Module /dev/foo not found." ]
