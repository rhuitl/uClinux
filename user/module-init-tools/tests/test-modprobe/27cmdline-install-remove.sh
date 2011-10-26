#! /bin/sh

for BITNESS in 32 64; do

MODTEST_OVERRIDE1=/lib/modules/$MODTEST_UNAME/modules.dep
MODTEST_OVERRIDE_WITH1=tests/tmp/modules.dep
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

MODTEST_OVERRIDE2=/lib/modules/$MODTEST_UNAME/noexport_nodep-$BITNESS.ko
MODTEST_OVERRIDE_WITH2=tests/data/$BITNESS/normal/noexport_nodep-$BITNESS.ko
export MODTEST_OVERRIDE2 MODTEST_OVERRIDE_WITH2

MODTEST_OVERRIDE3=/etc/modprobe.conf
MODTEST_OVERRIDE_WITH3=tests/tmp/modprobe.conf
export MODTEST_OVERRIDE3 MODTEST_OVERRIDE_WITH3

# Set up modules.dep file.
echo "# A comment" > tests/tmp/modules.dep
echo "/lib/modules/$MODTEST_UNAME/noexport_nodep-$BITNESS.ko:" >> tests/tmp/modules.dep

# Set up modprobe.conf file: one at end, one with text either side.
echo "options noexport_nodep-$BITNESS file-options" > tests/tmp/modprobe.conf
echo "install noexport_nodep-$BITNESS modprobe --ignore-install noexport_nodep-$BITNESS \$CMDLINE_OPTS" >> tests/tmp/modprobe.conf
echo "install othertarget echo \$CMDLINE_OPTS otheropts" >> tests/tmp/modprobe.conf

# With quoted args
[ "`modprobe noexport_nodep-$BITNESS 'foo="bar baz"' 2>&1`" = "SYSTEM: modprobe --ignore-install noexport_nodep-$BITNESS foo=\"bar baz\"" ]
# With unquoted args
[ "`modprobe noexport_nodep-$BITNESS foo=\"bar baz\" 2>&1`" = "SYSTEM: modprobe --ignore-install noexport_nodep-$BITNESS foo=\"bar baz\"" ]

# Same with other target.
[ "`modprobe othertarget 'foo="bar baz"' 2>&1`" = "SYSTEM: echo foo=\"bar baz\" otheropts" ]
# With unquoted args
[ "`modprobe othertarget foo=\"bar baz\" 2>&1`" = "SYSTEM: echo foo=\"bar baz\" otheropts" ]

done
