#! /bin/sh
# Test old-style module crap.
for BITNESS in 32 64; do

rm -rf tests/tmp/*
mkdir tests/tmp/drivers tests/tmp/other tests/tmp/drivers/type tests/tmp/other/type
cp tests/data/$BITNESS/normal/noexport_nodep-$BITNESS.ko tests/tmp/drivers/type/
cp tests/data/$BITNESS/normal/export_nodep-$BITNESS.ko tests/tmp/other/type/

MODTEST_OVERRIDE1=/lib/modules/$MODTEST_UNAME/modules.dep
MODTEST_OVERRIDE_WITH1=tests/tmp/modules.dep
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

MODTEST_OVERRIDE2=/lib/modules/$MODTEST_UNAME/type
MODTEST_OVERRIDE_WITH2=tests/tmp/type
export MODTEST_OVERRIDE2 MODTEST_OVERRIDE_WITH2

MODTEST_OVERRIDE3=/lib/modules/$MODTEST_UNAME/drivers/type/noexport_nodep-$BITNESS.ko
MODTEST_OVERRIDE_WITH3=tests/tmp/drivers/type/noexport_nodep-$BITNESS.ko
export MODTEST_OVERRIDE3 MODTEST_OVERRIDE_WITH3

MODTEST_OVERRIDE4=/lib/modules/$MODTEST_UNAME/other/type/export_nodep-$BITNESS.ko
MODTEST_OVERRIDE_WITH4=tests/tmp/other/type/export_nodep-$BITNESS.ko
export MODTEST_OVERRIDE4 MODTEST_OVERRIDE_WITH4

MODTEST_OVERRIDE5=/etc/modprobe.conf
MODTEST_OVERRIDE_WITH5=tests/tmp/DOES_NOT_EXIST
export MODTEST_OVERRIDE5 MODTEST_OVERRIDE_WITH5

# Set up modules.dep file.
echo "# A comment" > tests/tmp/modules.dep
echo "/lib/modules/$MODTEST_UNAME/drivers/type/noexport_nodep-$BITNESS.ko:" >> tests/tmp/modules.dep
echo "/lib/modules/$MODTEST_UNAME/other/type/export_nodep-$BITNESS.ko:" >> tests/tmp/modules.dep

SIZE1=$(echo `wc -c < tests/data/$BITNESS/normal/noexport_nodep-$BITNESS.ko`)
SIZE2=$(echo `wc -c < tests/data/$BITNESS/normal/export_nodep-$BITNESS.ko`)

# -l lists all of them (either order)
[ "`modprobe -l 2>&1`" = "/lib/modules/$MODTEST_UNAME/drivers/type/noexport_nodep-$BITNESS.ko
/lib/modules/$MODTEST_UNAME/other/type/export_nodep-$BITNESS.ko" ] ||
[ "`modprobe -l 2>&1`" = "/lib/modules/$MODTEST_UNAME/other/type/export_nodep-$BITNESS.ko
/lib/modules/$MODTEST_UNAME/drivers/type/noexport_nodep-$BITNESS.ko" ]

# -l -t foo lists none of them.
[ "`modprobe -l -t foo 2>&1`" = "" ]

# -l -t type lists all of them (either order)
[ "`modprobe -l -t type 2>&1`" = "/lib/modules/$MODTEST_UNAME/drivers/type/noexport_nodep-$BITNESS.ko
/lib/modules/$MODTEST_UNAME/other/type/export_nodep-$BITNESS.ko" ] ||
[ "`modprobe -l -t type 2>&1`" = "/lib/modules/$MODTEST_UNAME/other/type/export_nodep-$BITNESS.ko
/lib/modules/$MODTEST_UNAME/drivers/type/noexport_nodep-$BITNESS.ko" ]

# -l -t drivers lists one.
[ "`modprobe -l -t drivers 2>&1`" = "/lib/modules/$MODTEST_UNAME/drivers/type/noexport_nodep-$BITNESS.ko" ]

# -l -t drivers/type lists one.
[ "`modprobe -l -t drivers/type 2>&1`" = "/lib/modules/$MODTEST_UNAME/drivers/type/noexport_nodep-$BITNESS.ko" ]

# -l -t other lists one.
[ "`modprobe -l -t other 2>&1`" = "/lib/modules/$MODTEST_UNAME/other/type/export_nodep-$BITNESS.ko" ]

# -l -t other/type lists one.
[ "`modprobe -l -t other/type 2>&1`" = "/lib/modules/$MODTEST_UNAME/other/type/export_nodep-$BITNESS.ko" ]

# Wildcard works.
[ "`modprobe -l -t type 'noexport-nodep*' 2>&1`" = "/lib/modules/$MODTEST_UNAME/drivers/type/noexport_nodep-$BITNESS.ko" ]

# -t type without -l not supported
modprobe -t type 2>&1 | grep -q Usage
modprobe -a -t type 2>&1 | grep -q Usage

# -a with one arg succeeds.
[ "`modprobe -a noexport_nodep-$BITNESS 2>&1`" = "INIT_MODULE: $SIZE1 " ]
# ... even with - and _ confused.
[ "`modprobe -a noexport-nodep_$BITNESS 2>&1`" = "INIT_MODULE: $SIZE1 " ]

# With two args succeeds.
[ "`modprobe -a noexport_nodep-$BITNESS export_nodep-$BITNESS 2>&1`" = "INIT_MODULE: $SIZE1 
INIT_MODULE: $SIZE2 " ]

# Does second even if first screws up.
[ "`modprobe -a crap export_nodep-$BITNESS 2>&1`" = "WARNING: Module crap not found.
INIT_MODULE: $SIZE2 " ]

done
