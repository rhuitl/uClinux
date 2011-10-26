#! /bin/sh
# Test conversion of "alias" command when they are block or char majors.
# (now they need a wildcard for the minor).

TESTING_MODPROBE_CONF=tests/tmp/modules.conf
export TESTING_MODPROBE_CONF

echo 'alias char-major-17 a' > tests/tmp/modules.conf
echo 'alias block-major-12 b' >> tests/tmp/modules.conf

[ "`generate-modprobe.conf > tests/tmp/modprobe.conf 2>&1`" = "" ]
[ `grep -v '^#' < tests/tmp/modprobe.conf | wc -l` = 2 ]
[ "`grep ^alias tests/tmp/modprobe.conf`" = "alias char-major-17-* a
alias block-major-12-* b" ]

# Recursive
echo 'alias char-major-17 a-alias' > tests/tmp/modules.conf
echo 'alias a-alias a' >> tests/tmp/modules.conf
[ "`generate-modprobe.conf > tests/tmp/modprobe.conf 2>&1`" = "" ]
[ `grep -v '^#' < tests/tmp/modprobe.conf | wc -l` = 2 ]
[ "`grep ^alias tests/tmp/modprobe.conf`" = "alias char-major-17-* a
alias a-alias a" ]
