#! /bin/sh
# Test wildcard install/remove commands.

for BITNESS in 32 64; do

MODTEST_OVERRIDE1=/lib/modules/$MODTEST_UNAME/modules.dep
MODTEST_OVERRIDE_WITH1=/dev/null
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

MODTEST_OVERRIDE2=/etc/modprobe.conf
MODTEST_OVERRIDE_WITH2=tests/tmp/modprobe.conf
export MODTEST_OVERRIDE2 MODTEST_OVERRIDE_WITH2

MODTEST_DO_SYSTEM=1
export MODTEST_DO_SYSTEM

# Create a simple config file.
cat > tests/tmp/modprobe.conf <<EOF
# Various aliases
install *wildcard-_* echo installing \$MODPROBE_MODULE.
remove *wildcard-_* echo removing \$MODPROBE_MODULE.
EOF

# Install...
[ "`modprobe wildcard-_aaa 2>&1`" = "installing wildcard__aaa." ]
[ "`modprobe wildcard-_ 2>&1`" = "installing wildcard__." ]
[ "`modprobe wildcard_- 2>&1`" = "installing wildcard__." ]
[ "`modprobe anotherwildcard-_ 2>&1`" = "installing anotherwildcard__." ]
[ "`modprobe anotherwildcard-_aaa 2>&1`" = "installing anotherwildcard__aaa." ]

# Remove...
[ "`modprobe -r wildcard-_aaa 2>&1`" = "removing wildcard__aaa." ]
[ "`modprobe -r wildcard-_ 2>&1`" = "removing wildcard__." ]
[ "`modprobe -r wildcard_- 2>&1`" = "removing wildcard__." ]
[ "`modprobe -r anotherwildcard-_ 2>&1`" = "removing anotherwildcard__." ]
[ "`modprobe -r anotherwildcard-_aaa 2>&1`" = "removing anotherwildcard__aaa." ]

done
