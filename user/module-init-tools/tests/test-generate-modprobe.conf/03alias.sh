#! /bin/sh
# Test conversion of "alias" command.

TESTING_MODPROBE_CONF=tests/tmp/modules.conf
export TESTING_MODPROBE_CONF

# Simple.
echo 'alias dummy0 dummy' > tests/tmp/modules.conf
[ "`generate-modprobe.conf > tests/tmp/modprobe.conf 2>&1`" = "" ]
[ `grep -v '^#' < tests/tmp/modprobe.conf | wc -l` = 1 ]
[ "`grep ^alias tests/tmp/modprobe.conf`" = "alias dummy0 dummy" ]

# Recursive
echo 'alias dummy0 dummy' > tests/tmp/modules.conf
echo 'alias dummy0-alias dummy0' >> tests/tmp/modules.conf
[ "`generate-modprobe.conf > tests/tmp/modprobe.conf 2>&1`" = "" ]
[ `grep -v '^#' < tests/tmp/modprobe.conf | wc -l` = 2 ]
[ "`grep ^alias tests/tmp/modprobe.conf`" = "alias dummy0 dummy
alias dummy0-alias dummy" ]

# Chasing options (FIXME: FAILS)
#echo 'options dummy0-alias dummy0-alias-options' >> tests/tmp/modules.conf
#echo 'options dummy0 dummy0-options' >> tests/tmp/modules.conf
#[ "`generate-modprobe.conf > tests/tmp/modprobe.conf 2>&1`" = "" ]
#[ `grep -v '^#' < tests/tmp/modprobe.conf | wc -l` = 4 ]
#[ "`grep ^alias tests/tmp/modprobe.conf`" = "alias dummy0 dummy
#alias dummy0-alias dummy" ]
#[ "`grep '^options dummy0 ' tests/tmp/modprobe.conf`" = "options dummy0 dummy0-options" ]
#[ "`grep '^options dummy0-alias ' tests/tmp/modprobe.conf`" = "options dummy0-alias dummy0-options dummy0-alias-options" ]
