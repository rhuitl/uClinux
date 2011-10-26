#! /bin/sh
# Test for blacklist usage.

for BITNESS in 32 64; do

MODTEST_OVERRIDE1=/lib/modules/$MODTEST_UNAME/modules.dep
MODTEST_OVERRIDE_WITH1=tests/tmp/modules.dep
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

MODTEST_OVERRIDE2=/etc/modprobe.conf
MODTEST_OVERRIDE_WITH2=tests/tmp/modprobe.conf
export MODTEST_OVERRIDE2 MODTEST_OVERRIDE_WITH2

MODTEST_OVERRIDE3=/lib/modules/$MODTEST_UNAME/modules.alias
MODTEST_OVERRIDE_WITH3=tests/tmp/modules.alias
export MODTEST_OVERRIDE3 MODTEST_OVERRIDE_WITH3

MODTEST_OVERRIDE4=/lib/modules/$MODTEST_UNAME/modules.symbols
MODTEST_OVERRIDE_WITH4=/dev/null
export MODTEST_OVERRIDE4 MODTEST_OVERRIDE_WITH4

MODTEST_OVERRIDE5=/lib/modules/$MODTEST_UNAME/kernel/alias-$BITNESS.ko
MODTEST_OVERRIDE_WITH5=tests/data/$BITNESS/alias/alias-$BITNESS.ko
export MODTEST_OVERRIDE5 MODTEST_OVERRIDE_WITH5

MODTEST_OVERRIDE6=/lib/modules/$MODTEST_UNAME/kernel/foo.ko
MODTEST_OVERRIDE_WITH6=tests/tmp/foo.ko
export MODTEST_OVERRIDE6 MODTEST_OVERRIDE_WITH6

MODTEST_OVERRIDE7=/etc/modprobe.d
MODTEST_OVERRIDE_WITH7=NOSUCHFILENAME
export MODTEST_OVERRIDE7 MODTEST_OVERRIDE_WITH7

SIZE=$(echo `wc -c < tests/data/$BITNESS/alias/alias-$BITNESS.ko`)

echo "/lib/modules/$MODTEST_UNAME/kernel/alias-$BITNESS.ko:" > tests/tmp/modules.dep
echo "/lib/modules/$MODTEST_UNAME/kernel/foo.ko:" >> tests/tmp/modules.dep
rm -f tests/tmp/modules.alias
rm -f tests/tmp/modprobe.conf
echo Test > tests/tmp/foo.ko

# First, alias found in modules.alias works.
echo "alias bar alias-$BITNESS" > tests/tmp/modules.alias
[ "`modprobe bar 2>&1`" = "INIT_MODULE: $SIZE " ]

# Blacklist makes it fail.
echo "blacklist alias-$BITNESS" > tests/tmp/modprobe.conf
[ "`modprobe bar 2>&1`" = "FATAL: Module bar not found." ]

# Blacklist doesn't effect other aliases.
echo "alias bar foo" >> tests/tmp/modules.alias
[ "`modprobe bar 2>&1`" = "INIT_MODULE: 5 " ]

# Blacklist both.
echo "blacklist foo" >> tests/tmp/modprobe.conf
[ "`modprobe bar 2>&1`" = "FATAL: Module bar not found." ]

# Remove blacklist, all works.
rm -f tests/tmp/modprobe.conf
RESULT="`modprobe bar 2>&1`"
[ "$RESULT" = "INIT_MODULE: $SIZE 
INIT_MODULE: 5 " ] || [ "$RESULT" = "INIT_MODULE: 5 
INIT_MODULE: $SIZE " ]
done
