#! /bin/sh
# Test wildcard aliases.

for BITNESS in 32 64; do

MODTEST_OVERRIDE1=/lib/modules/$MODTEST_UNAME/modules.dep
MODTEST_OVERRIDE_WITH1=/dev/null
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

MODTEST_OVERRIDE2=/etc/modprobe.conf
MODTEST_OVERRIDE_WITH2=tests/tmp/modprobe.conf
export MODTEST_OVERRIDE2 MODTEST_OVERRIDE_WITH2

# Create a simple config file.
cat > tests/tmp/modprobe.conf <<EOF
# Various aliases
alias *wildcard-_* foo
alias /dev/test* bar
EOF

# Simple test.
[ "`modprobe wildcard-_aaa 2>&1`" = "FATAL: Module foo not found." ]
[ "`modprobe wildcard-_ 2>&1`" = "FATAL: Module foo not found." ]
[ "`modprobe wildcard_- 2>&1`" = "FATAL: Module foo not found." ]
[ "`modprobe anotherwildcard-_ 2>&1`" = "FATAL: Module foo not found." ]
[ "`modprobe anotherwildcard-_aaa 2>&1`" = "FATAL: Module foo not found." ]
[ "`modprobe /dev/test 2>&1`" = "FATAL: Module bar not found." ]
[ "`modprobe /dev/test/tmp 2>&1`" = "FATAL: Module bar not found." ]
[ "`modprobe /dev/test7  2>&1`" = "FATAL: Module bar not found." ]

done
