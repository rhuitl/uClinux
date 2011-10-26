#! /bin/sh

# Test modinfo extraction: works for *any* endiannes.
for ENDIAN in -le -be; do
for BITNESS in 32 64; do

# Inputs
MODTEST_OVERRIDE1=/lib/modules/$MODTEST_UNAME/modules.dep
MODTEST_OVERRIDE_WITH1=tests/tmp/modules.dep
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

MODTEST_OVERRIDE2=/lib/modules/$MODTEST_UNAME/modinfo-$BITNESS.ko
MODTEST_OVERRIDE_WITH2=tests/data/$BITNESS$ENDIAN/modinfo/modinfo-$BITNESS.ko
export MODTEST_OVERRIDE2 MODTEST_OVERRIDE_WITH2

echo "/lib/modules/$MODTEST_UNAME/modinfo-$BITNESS.ko: /lib/modules/$MODTEST_UNAME/modinfo-crap-$BITNESS.ko" > tests/tmp/modules.dep

# Test individual field extraction: by module search and abs. path
for file in modinfo-$BITNESS tests/data/$BITNESS$ENDIAN/modinfo/modinfo-$BITNESS.ko; do
    [ "`modinfo -F randomcrap $file 2>&1`" = "my random crap which I use to test stuff with" ]
    [ "`modinfo -F vermagic $file 2>&1`" = "my magic" ]
    [ "`modinfo -F author $file 2>&1`" = "AUTHOR" ]
    [ "`modinfo -a $file 2>&1`" = "AUTHOR" ]
    [ "`modinfo -F description $file 2>&1`" = "DESCRIPTION" ]
    [ "`modinfo -d $file 2>&1`" = "DESCRIPTION" ]
    [ "`modinfo -F alias $file 2>&1`" = "ALIAS1
ALIAS2" ] || [ "`modinfo -F alias $file 2>&1`" = "ALIAS2
ALIAS1" ]
    [ "`modinfo -F parm $file 2>&1`" = "foo:The number of foos on the card
described:A well-described parameter" ] ||
    [ "`modinfo -F parm $file 2>&1`" = "described:A well-described parameter
foo:The number of foos on the card" ]

    [ "`modinfo -F parmtype $file 2>&1`" = "described:uint
undescribed:int" ] ||
    [ "`modinfo -F parmtype $file 2>&1`" = "undescribed:int
described:uint" ]
    [ "`modinfo -F unknown $file 2>&1`" = "" ]
done

# Test filename output
[ "`modinfo -F filename modinfo-$BITNESS 2>&1`" = "/lib/modules/$MODTEST_UNAME/modinfo-$BITNESS.ko" ]
[ "`modinfo -n modinfo-$BITNESS 2>&1`" = "/lib/modules/$MODTEST_UNAME/modinfo-$BITNESS.ko" ]
[ "`modinfo -F filename tests/data/$BITNESS$ENDIAN/modinfo/modinfo-$BITNESS.ko 2>&1`" = "tests/data/$BITNESS$ENDIAN/modinfo/modinfo-$BITNESS.ko" ]
[ "`modinfo -n tests/data/$BITNESS$ENDIAN/modinfo/modinfo-$BITNESS.ko 2>&1`" = "tests/data/$BITNESS$ENDIAN/modinfo/modinfo-$BITNESS.ko" ]

# Test multiple modules on cmdline.
[ "`modinfo -F vermagic tests/data/$BITNESS$ENDIAN/modinfo/modinfo-$BITNESS.ko tests/data/$BITNESS$ENDIAN/modinfo/modinfo-$BITNESS.ko 2>&1`" = "my magic
my magic" ]

# Test 0-fill
[ "`modinfo -0 -F alias tests/data/$BITNESS$ENDIAN/modinfo/modinfo-$BITNESS.ko 2>&1 | tr '\000' @`" = "ALIAS1@ALIAS2@" ]

done
done
