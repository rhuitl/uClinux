#! /bin/sh

MODTEST_OVERRIDE1=/proc/modules
MODTEST_OVERRIDE_WITH1=/dev/null

export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

# This should be true
[ "`lsmod`" = "Module                  Size  Used by" ]
