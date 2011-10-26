#! /bin/sh
# Test for modules.alias usage.

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

# Shouldn't complain if can't open modules.alias
[ "`modprobe bar 2>&1`" = "FATAL: Module bar not found." ]

# Now, alias found in modules.alias works.
echo "alias bar alias-$BITNESS" > tests/tmp/modules.alias
[ "`modprobe bar 2>&1`" = "INIT_MODULE: $SIZE " ]

# Normal alias should override it.
echo 'alias bar foo' > tests/tmp/modprobe.conf
[ "`modprobe foo 2>&1`" = "INIT_MODULE: 5 " ]

# If there's a real module, alias from modules.alias must NOT override.
echo "alias foo alias-$BITNESS" > tests/tmp/modules.alias
[ "`modprobe foo 2>&1`" = "INIT_MODULE: 5 " ]

# If there's an install command, modules.alias must not override.
echo 'install bar echo foo' > tests/tmp/modprobe.conf
[ "`modprobe bar 2>&1`" = "SYSTEM: echo foo" ]
echo 'remove bar echo foo remove' > tests/tmp/modprobe.conf
[ "`modprobe -r bar 2>&1`" = "SYSTEM: echo foo remove" ]

# Should gather up options from other alias name as well.
echo "alias bar alias-$BITNESS" > tests/tmp/modules.alias
echo "options bar option1" > tests/tmp/modprobe.conf
echo "options alias-$BITNESS option2" >> tests/tmp/modprobe.conf
[ "`modprobe bar 2>&1`" = "INIT_MODULE: $SIZE option1 option2" ]

# Duplicated alias: both get probed (either order)
echo "alias bar foo" >> tests/tmp/modules.alias
OUT="`modprobe bar 2>&1`"

[ "$OUT" = "INIT_MODULE: $SIZE option1 option2
INIT_MODULE: 5 option1" ] || [ "$OUT" = "INIT_MODULE: 5 option1
INIT_MODULE: $SIZE option1 option2" ]
done
