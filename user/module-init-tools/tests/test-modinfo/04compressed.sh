#! /bin/sh
# Test modinfo extraction on compressed modules.

[ -n "$CONFIG_HAVE_ZLIB" ] || exit 0

for ENDIAN in -le -be; do
for BITNESS in 32 64; do

gzip < tests/data/$BITNESS$ENDIAN/modinfo/modinfo-$BITNESS.ko > tests/tmp/modinfo-$BITNESS.ko.gz

# Inputs
MODTEST_OVERRIDE1=/lib/modules/$MODTEST_UNAME/modules.dep
MODTEST_OVERRIDE_WITH1=tests/tmp/modules.dep
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

MODTEST_OVERRIDE2=/lib/modules/$MODTEST_UNAME/modinfo-$BITNESS.ko.gz
MODTEST_OVERRIDE_WITH2=tests/tmp/modinfo-$BITNESS.ko.gz
export MODTEST_OVERRIDE2 MODTEST_OVERRIDE_WITH2

echo "/lib/modules/$MODTEST_UNAME/modinfo-$BITNESS.ko.gz: /lib/modules/$MODTEST_UNAME/modinfo-crap-$BITNESS.ko.gz" > tests/tmp/modules.dep

# Test individual field extraction: by module search and abs. path
for file in modinfo-$BITNESS tests/tmp/modinfo-$BITNESS.ko.gz; do
    [ "`modinfo -F randomcrap $file 2>&1`" = "my random crap which I use to test stuff with" ]
    [ "`modinfo -F vermagic $file 2>&1`" = "my magic" ]
    [ "`modinfo -F author $file 2>&1`" = "AUTHOR" ]
    [ "`modinfo -F description $file 2>&1`" = "DESCRIPTION" ]
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

# Test multiple modules on cmdline.
[ "`modinfo -F vermagic tests/tmp/modinfo-$BITNESS.ko.gz tests/tmp/modinfo-$BITNESS.ko.gz 2>&1`" = "my magic
my magic" ]

# Test 0-fill
[ "`modinfo -0 -F alias tests/tmp/modinfo-$BITNESS.ko.gz 2>&1 | tr '\000' @`" = "ALIAS1@ALIAS2@" ]

done
done
