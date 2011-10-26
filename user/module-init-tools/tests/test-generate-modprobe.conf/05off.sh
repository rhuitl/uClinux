#! /bin/sh
# Test conversion of "alias" command when they are for off or null.

TESTING_MODPROBE_CONF=tests/tmp/modules.conf
export TESTING_MODPROBE_CONF

echo 'alias net-pf-1 off' > tests/tmp/modules.conf
echo 'alias net-pf-2 null' >> tests/tmp/modules.conf
echo 'add alias net-pf-3 off' >> tests/tmp/modules.conf
echo 'add alias net-pf-4 null' >> tests/tmp/modules.conf

[ "`generate-modprobe.conf > tests/tmp/modprobe.conf 2>&1`" = "" ]
[ `grep -v '^#' < tests/tmp/modprobe.conf | wc -l` = 4 ]
[ "`grep ^install tests/tmp/modprobe.conf`" = "install net-pf-1 /bin/true
install net-pf-2 /bin/true
install net-pf-3 /bin/true
install net-pf-4 /bin/true" ]
