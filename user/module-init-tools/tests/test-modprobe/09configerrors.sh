#! /bin/sh

# Test various config file errors.
MODTEST_OVERRIDE1=/lib/modules/$MODTEST_UNAME/modules.dep
MODTEST_OVERRIDE_WITH1=/dev/null
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

MODTEST_OVERRIDE2=/etc/modprobe.conf
MODTEST_OVERRIDE_WITH2=tests/tmp/modprobe.conf
export MODTEST_OVERRIDE2 MODTEST_OVERRIDE_WITH2

# Test bad alias syntax
cat > tests/tmp/modprobe.conf <<EOF
alias
alias foo
EOF

[ "`modprobe foo 2>&1`" = "WARNING: /etc/modprobe.conf line 1: ignoring bad line starting with 'alias'
WARNING: /etc/modprobe.conf line 2: ignoring bad line starting with 'alias'
FATAL: Module foo not found." ]

# Bad option syntax
cat > tests/tmp/modprobe.conf <<EOF
options
options foo
EOF

[ "`modprobe foo 2>&1`" = "WARNING: /etc/modprobe.conf line 1: ignoring bad line starting with 'options'
WARNING: /etc/modprobe.conf line 2: ignoring bad line starting with 'options'
FATAL: Module foo not found." ]

# Bad include syntax
cat > tests/tmp/modprobe.conf <<EOF
include
EOF

[ "`modprobe foo 2>&1`" = "WARNING: /etc/modprobe.conf line 1: ignoring bad line starting with 'include'
FATAL: Module foo not found." ]

# Bad install syntax
cat > tests/tmp/modprobe.conf <<EOF
install
install foo
EOF

[ "`modprobe foo 2>&1`" = "WARNING: /etc/modprobe.conf line 1: ignoring bad line starting with 'install'
WARNING: /etc/modprobe.conf line 2: ignoring bad line starting with 'install'
FATAL: Module foo not found." ]

# Bad remove syntax
cat > tests/tmp/modprobe.conf <<EOF
remove
remove foo
EOF

[ "`modprobe foo 2>&1`" = "WARNING: /etc/modprobe.conf line 1: ignoring bad line starting with 'remove'
WARNING: /etc/modprobe.conf line 2: ignoring bad line starting with 'remove'
FATAL: Module foo not found." ]

# Complete junk
cat > tests/tmp/modprobe.conf <<EOF
complete junk and stuff
rubbish
EOF

[ "`modprobe foo 2>&1`" = "WARNING: /etc/modprobe.conf line 1: ignoring bad line starting with 'complete'
WARNING: /etc/modprobe.conf line 2: ignoring bad line starting with 'rubbish'
FATAL: Module foo not found." ]

# Line numbering counted correctly.
echo "#comment" > tests/tmp/modprobe.conf
echo "remove" >> tests/tmp/modprobe.conf

[ "`modprobe foo 2>&1`" = "WARNING: /etc/modprobe.conf line 2: ignoring bad line starting with 'remove'
FATAL: Module foo not found." ]

echo "" > tests/tmp/modprobe.conf
echo "remove" >> tests/tmp/modprobe.conf

[ "`modprobe foo 2>&1`" = "WARNING: /etc/modprobe.conf line 2: ignoring bad line starting with 'remove'
FATAL: Module foo not found." ]

echo "  # Comment" > tests/tmp/modprobe.conf
echo "remove" >> tests/tmp/modprobe.conf

[ "`modprobe foo 2>&1`" = "WARNING: /etc/modprobe.conf line 2: ignoring bad line starting with 'remove'
FATAL: Module foo not found." ]

echo "  # Comment \\" > tests/tmp/modprobe.conf
echo "with multiple lines" >> tests/tmp/modprobe.conf
echo "remove" >> tests/tmp/modprobe.conf

[ "`modprobe foo 2>&1`" = "WARNING: /etc/modprobe.conf line 3: ignoring bad line starting with 'remove'
FATAL: Module foo not found." ]

echo "remove foo \\" > tests/tmp/modprobe.conf
echo "  bar" >> tests/tmp/modprobe.conf
echo "remove" >> tests/tmp/modprobe.conf
[ "`modprobe foo 2>&1`" = "WARNING: /etc/modprobe.conf line 3: ignoring bad line starting with 'remove'
FATAL: Module foo not found." ]


