#! /bin/sh
# Test conversion of "options" command.

# Simple.
echo 'options dummy0 dummy0-options' > tests/tmp/modules.conf

TESTING_MODPROBE_CONF=tests/tmp/modules.conf
export TESTING_MODPROBE_CONF

[ "`generate-modprobe.conf > tests/tmp/modprobe.conf 2>&1`" = "" ]

[ `grep -v '^#' < tests/tmp/modprobe.conf | wc -l` = 1 ]
[ "`grep ^options tests/tmp/modprobe.conf`" = "options dummy0 dummy0-options" ]

# Command line args.
echo 'options dummy0 -o dummy0' > tests/tmp/modules.conf

[ "`generate-modprobe.conf > tests/tmp/modprobe.conf 2>&1`" = "" ]

[ `grep -v '^#' < tests/tmp/modprobe.conf | wc -l` = 1 ]
[ "`grep ^install tests/tmp/modprobe.conf`" = "install dummy0 /sbin/modprobe -o dummy0 --ignore-install dummy0" ]

# Both
echo 'options dummy0 -o dummy0 dummy0-options' > tests/tmp/modules.conf

[ "`generate-modprobe.conf > tests/tmp/modprobe.conf 2>&1`" = "" ]
[ `grep -v '^#' < tests/tmp/modprobe.conf | wc -l` = 2 ]
[ "`grep ^install tests/tmp/modprobe.conf`" = "install dummy0 /sbin/modprobe -o dummy0 --ignore-install dummy0" ]
[ "`grep ^options tests/tmp/modprobe.conf`" = "options dummy0 dummy0-options" ]

echo 'options dummy0 dummy0-options -o dummy0' > tests/tmp/modules.conf

[ "`generate-modprobe.conf > tests/tmp/modprobe.conf 2>&1`" = "" ]
[ `grep -v '^#' < tests/tmp/modprobe.conf | wc -l` = 2 ]
[ "`grep ^install tests/tmp/modprobe.conf`" = "install dummy0 /sbin/modprobe -o dummy0 --ignore-install dummy0" ]
[ "`grep ^options tests/tmp/modprobe.conf`" = "options dummy0 dummy0-options" ]
