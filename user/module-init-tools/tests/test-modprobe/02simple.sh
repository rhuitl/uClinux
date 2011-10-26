#! /bin/sh

for BITNESS in 32 64; do

MODTEST_OVERRIDE1=/lib/modules/$MODTEST_UNAME/modules.dep
MODTEST_OVERRIDE_WITH1=tests/tmp/modules.dep
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

MODTEST_OVERRIDE2=/lib/modules/$MODTEST_UNAME/noexport_nodep-$BITNESS.ko
MODTEST_OVERRIDE_WITH2=tests/data/$BITNESS/normal/noexport_nodep-$BITNESS.ko
export MODTEST_OVERRIDE2 MODTEST_OVERRIDE_WITH2

MODTEST_OVERRIDE3=/etc/modprobe.conf
MODTEST_OVERRIDE_WITH3=tests/tmp/DOES_NOT_EXIST
export MODTEST_OVERRIDE3 MODTEST_OVERRIDE_WITH3

# Set up modules.dep file.
echo "# A comment" > tests/tmp/modules.dep
echo "/lib/modules/$MODTEST_UNAME/noexport_nodep-$BITNESS.ko:" >> tests/tmp/modules.dep

SIZE=$(echo `wc -c < tests/data/$BITNESS/normal/noexport_nodep-$BITNESS.ko`)

# No args
[ "`modprobe noexport_nodep-$BITNESS 2>&1`" = "INIT_MODULE: $SIZE " ]

# With quoted args
[ "`modprobe noexport_nodep-$BITNESS 'foo="bar baz"' 2>&1`" = "INIT_MODULE: $SIZE foo=\"bar baz\"" ]
# With unquoted args
[ "`modprobe noexport_nodep-$BITNESS foo=\"bar baz\" 2>&1`" = "INIT_MODULE: $SIZE foo=\"bar baz\"" ]

# Check underscore equivalence.
[ "`modprobe noexport-nodep-$BITNESS foo=\"bar baz\" 2>&1`" = "INIT_MODULE: $SIZE foo=\"bar baz\"" ]
[ "`modprobe noexport-nodep_$BITNESS foo=\"bar baz\" 2>&1`" = "INIT_MODULE: $SIZE foo=\"bar baz\"" ]
[ "`modprobe noexport_nodep_$BITNESS foo=\"bar baz\" 2>&1`" = "INIT_MODULE: $SIZE foo=\"bar baz\"" ]

done
