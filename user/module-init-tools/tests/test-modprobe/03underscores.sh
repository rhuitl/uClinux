#! /bin/sh
# Check underscore synonymity everywhere.

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

MODTEST_OVERRIDE4=include-_
MODTEST_OVERRIDE_WITH4=tests/tmp/modprobe.conf.included
export MODTEST_OVERRIDE4 MODTEST_OVERRIDE_WITH4

MODTEST_OVERRIDE5=/proc/modules
MODTEST_OVERRIDE_WITH5=FILE-WHICH-DOESNT-EXIST
export MODTEST_OVERRIDE5 MODTEST_OVERRIDE_WITH5

MODTEST_OVERRIDE6=/lib/modules/$MODTEST_UNAME/export_nodep-$BITNESS.ko
MODTEST_OVERRIDE_WITH6=tests/data/$BITNESS/normal/export_nodep-$BITNESS.ko
export MODTEST_OVERRIDE6 MODTEST_OVERRIDE_WITH6

# Set up modules.dep file.
echo "# A comment" > tests/tmp/modules.dep
echo "/lib/modules/$MODTEST_UNAME/noexport_nodep-$BITNESS.ko:" >> tests/tmp/modules.dep
echo "/lib/modules/$MODTEST_UNAME/export_nodep-$BITNESS.ko:" >> tests/tmp/modules.dep

# Set up config file.
echo "alias alias-_ noexport-nodep_$BITNESS" > tests/tmp/modprobe.conf
echo "options export-nodep_$BITNESS option-_" >> tests/tmp/modprobe.conf
echo "install test-_ echo install-_" >> tests/tmp/modprobe.conf
echo "remove test-_ echo remove-_" >> tests/tmp/modprobe.conf
echo "include include-_" >> tests/tmp/modprobe.conf
echo "install test-include echo Included" >> tests/tmp/modprobe.conf.included

SIZE1=$(echo `wc -c < tests/data/$BITNESS/normal/noexport_nodep-$BITNESS.ko`)
SIZE2=$(echo `wc -c < tests/data/$BITNESS/normal/export_nodep-$BITNESS.ko`)

# On command line (-r and normal)
[ "`modprobe noexport-nodep_$BITNESS 2>&1`" = "INIT_MODULE: $SIZE1 " ]
[ "`modprobe -r noexport-nodep_$BITNESS 2>&1`" = "DELETE_MODULE: noexport_nodep_$BITNESS EXCL " ]

# In alias commands (source and target)
[ "`modprobe alias-_ 2>&1`" = "INIT_MODULE: $SIZE1 " ]
[ "`modprobe alias_- 2>&1`" = "INIT_MODULE: $SIZE1 " ]
[ "`modprobe -r alias-_ 2>&1`" = "DELETE_MODULE: noexport_nodep_$BITNESS EXCL " ]
[ "`modprobe -r alias_- 2>&1`" = "DELETE_MODULE: noexport_nodep_$BITNESS EXCL " ]

# In option commands (NOT in arguments)
[ "`modprobe export_nodep-$BITNESS 2>&1`" = "INIT_MODULE: $SIZE2 option-_" ]
[ "`modprobe export-nodep_$BITNESS 2>&1`" = "INIT_MODULE: $SIZE2 option-_" ]

# In install commands
[ "`modprobe test-_ 2>&1`" = "SYSTEM: echo install-_" ]
[ "`modprobe test_- 2>&1`" = "SYSTEM: echo install-_" ]

# In remove commands
[ "`modprobe -r test-_ 2>&1`" = "SYSTEM: echo remove-_" ]
[ "`modprobe -r test_- 2>&1`" = "SYSTEM: echo remove-_" ]

# NOT in include commands
[ "`modprobe test-include 2>&1`" = "SYSTEM: echo Included" ]
[ "`modprobe test_include 2>&1`" = "SYSTEM: echo Included" ]

done
