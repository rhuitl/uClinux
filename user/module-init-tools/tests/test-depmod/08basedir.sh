#! /bin/sh
# Simple tests of generation of 32-bit and 64-bit modules.dep with basedir

for ENDIAN in -le -be; do
for BITNESS in 32 64; do

# Inputs
MODTEST_OVERRIDE1=/BASEDIR/lib/modules/$MODTEST_UNAME
MODTEST_OVERRIDE_WITH1=tests/data/$BITNESS$ENDIAN/normal
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

MODTEST_OVERRIDE2=/BASEDIR/lib/modules/$MODTEST_UNAME/export_dep-$BITNESS.ko
MODTEST_OVERRIDE_WITH2=tests/data/$BITNESS$ENDIAN/normal/export_dep-$BITNESS.ko
export MODTEST_OVERRIDE2 MODTEST_OVERRIDE_WITH2

MODTEST_OVERRIDE3=/BASEDIR/lib/modules/$MODTEST_UNAME/noexport_dep-$BITNESS.ko
MODTEST_OVERRIDE_WITH3=tests/data/$BITNESS$ENDIAN/normal/noexport_dep-$BITNESS.ko
export MODTEST_OVERRIDE3 MODTEST_OVERRIDE_WITH3

MODTEST_OVERRIDE4=/BASEDIR/lib/modules/$MODTEST_UNAME/noexport_nodep-$BITNESS.ko
MODTEST_OVERRIDE_WITH4=tests/data/$BITNESS$ENDIAN/normal/noexport_nodep-$BITNESS.ko
export MODTEST_OVERRIDE4 MODTEST_OVERRIDE_WITH4

MODTEST_OVERRIDE5=/BASEDIR/lib/modules/$MODTEST_UNAME/export_nodep-$BITNESS.ko
MODTEST_OVERRIDE_WITH5=tests/data/$BITNESS$ENDIAN/normal/export_nodep-$BITNESS.ko
export MODTEST_OVERRIDE5 MODTEST_OVERRIDE_WITH5

MODTEST_OVERRIDE6=/BASEDIR/lib/modules/$MODTEST_UNAME/noexport_doubledep-$BITNESS.ko
MODTEST_OVERRIDE_WITH6=tests/data/$BITNESS$ENDIAN/normal/noexport_doubledep-$BITNESS.ko
export MODTEST_OVERRIDE6 MODTEST_OVERRIDE_WITH6

# Outputs
MODTEST_OVERRIDE7=/BASEDIR/lib/modules/$MODTEST_UNAME/modules.dep
MODTEST_OVERRIDE_WITH7=tests/tmp/modules.dep
export MODTEST_OVERRIDE7 MODTEST_OVERRIDE_WITH7

MODTEST_OVERRIDE8=/BASEDIR/lib/modules/$MODTEST_UNAME/modules.pcimap
MODTEST_OVERRIDE_WITH8=tests/tmp/modules.pcimap
export MODTEST_OVERRIDE8 MODTEST_OVERRIDE_WITH8

MODTEST_OVERRIDE9=/BASEDIR/lib/modules/$MODTEST_UNAME/modules.usbmap
MODTEST_OVERRIDE_WITH9=tests/tmp/modules.usbmap
export MODTEST_OVERRIDE9 MODTEST_OVERRIDE_WITH9

MODTEST_OVERRIDE10=/BASEDIR/lib/modules/$MODTEST_UNAME/modules.ccwmap
MODTEST_OVERRIDE_WITH10=tests/tmp/modules.ccwmap
export MODTEST_OVERRIDE10 MODTEST_OVERRIDE_WITH10

MODTEST_OVERRIDE11=/BASEDIR/lib/modules/$MODTEST_UNAME/modules.alias
MODTEST_OVERRIDE_WITH11=tests/tmp/modules.alias
export MODTEST_OVERRIDE11 MODTEST_OVERRIDE_WITH11

MODTEST_OVERRIDE12=/BASEDIR/lib/modules/$MODTEST_UNAME/modules.symbols
MODTEST_OVERRIDE_WITH12=tests/tmp/modules.symbols
export MODTEST_OVERRIDE12 MODTEST_OVERRIDE_WITH12

MODTEST_OVERRIDE13=/BASEDIR/lib/modules/$MODTEST_UNAME/modules.ieee1394map
MODTEST_OVERRIDE_WITH13=tests/tmp/modules.ieee1394map
export MODTEST_OVERRIDE13 MODTEST_OVERRIDE_WITH13

MODTEST_OVERRIDE14=/BASEDIR/lib/modules/$MODTEST_UNAME/modules.dep.temp
MODTEST_OVERRIDE_WITH14=tests/tmp/modules.dep.temp
export MODTEST_OVERRIDE14 MODTEST_OVERRIDE_WITH14

MODTEST_OVERRIDE15=/BASEDIR/lib/modules/$MODTEST_UNAME/modules.pcimap.temp
MODTEST_OVERRIDE_WITH15=tests/tmp/modules.pcimap.temp
export MODTEST_OVERRIDE15 MODTEST_OVERRIDE_WITH15

MODTEST_OVERRIDE16=/BASEDIR/lib/modules/$MODTEST_UNAME/modules.usbmap.temp
MODTEST_OVERRIDE_WITH16=tests/tmp/modules.usbmap.temp
export MODTEST_OVERRIDE16 MODTEST_OVERRIDE_WITH16

MODTEST_OVERRIDE17=/BASEDIR/lib/modules/$MODTEST_UNAME/modules.ccwmap.temp
MODTEST_OVERRIDE_WITH17=tests/tmp/modules.ccwmap.temp
export MODTEST_OVERRIDE17 MODTEST_OVERRIDE_WITH17

MODTEST_OVERRIDE18=/BASEDIR/lib/modules/$MODTEST_UNAME/modules.alias.temp
MODTEST_OVERRIDE_WITH18=tests/tmp/modules.alias.temp
export MODTEST_OVERRIDE18 MODTEST_OVERRIDE_WITH18

MODTEST_OVERRIDE19=/BASEDIR/lib/modules/$MODTEST_UNAME/modules.symbols.temp
MODTEST_OVERRIDE_WITH19=tests/tmp/modules.symbols.temp
export MODTEST_OVERRIDE19 MODTEST_OVERRIDE_WITH19

MODTEST_OVERRIDE20=/BASEDIR/lib/modules/$MODTEST_UNAME/modules.ieee1394map.temp
MODTEST_OVERRIDE_WITH20=tests/tmp/modules.ieee1394map.temp
export MODTEST_OVERRIDE20 MODTEST_OVERRIDE_WITH20

MODTEST_OVERRIDE21=/BASEDIR/lib/modules/$MODTEST_UNAME/modules.isapnpmap.temp
MODTEST_OVERRIDE_WITH21=tests/tmp/modules.isapnpmap.temp
export MODTEST_OVERRIDE21 MODTEST_OVERRIDE_WITH21

MODTEST_OVERRIDE22=/BASEDIR/lib/modules/$MODTEST_UNAME/modules.isapnpmap
MODTEST_OVERRIDE_WITH22=tests/tmp/modules.isapnpmap
export MODTEST_OVERRIDE22 MODTEST_OVERRIDE_WITH22

MODTEST_OVERRIDE23=/BASEDIR/lib/modules/$MODTEST_UNAME/modules.inputmap.temp
MODTEST_OVERRIDE_WITH23=tests/tmp/modules.inputmap.temp
export MODTEST_OVERRIDE23 MODTEST_OVERRIDE_WITH23

MODTEST_OVERRIDE24=/BASEDIR/lib/modules/$MODTEST_UNAME/modules.inputmap
MODTEST_OVERRIDE_WITH24=tests/tmp/modules.inputmap
export MODTEST_OVERRIDE24 MODTEST_OVERRIDE_WITH24

MODTEST_OVERRIDE25=/BASEDIR/lib/modules/$MODTEST_UNAME/modules.seriomap.temp
MODTEST_OVERRIDE_WITH25=tests/tmp/modules.seriomap.temp
export MODTEST_OVERRIDE25 MODTEST_OVERRIDE_WITH25

MODTEST_OVERRIDE26=/BASEDIR/lib/modules/$MODTEST_UNAME/modules.seriomap
MODTEST_OVERRIDE_WITH26=tests/tmp/modules.seriomap
export MODTEST_OVERRIDE26 MODTEST_OVERRIDE_WITH26

MODTEST_OVERRIDE27=/BASEDIR/lib/modules/$MODTEST_UNAME/modules.ofmap
MODTEST_OVERRIDE_WITH27=tests/tmp/modules.ofmap
export MODTEST_OVERRIDE27 MODTEST_OVERRIDE_WITH27

MODTEST_OVERRIDE28=/BASEDIR/lib/modules/$MODTEST_UNAME/modules.ofmap.temp
MODTEST_OVERRIDE_WITH28=tests/tmp/modules.ofmap.temp
export MODTEST_OVERRIDE28 MODTEST_OVERRIDE_WITH28

# Expect no output.
[ "`depmod -b /BASEDIR 2>&1`" = "" ]

# Check results: expect 5 lines
[ `grep -vc '^#' < tests/tmp/modules.dep` = 5 ]

[ "`grep -w export_dep-$BITNESS.ko: tests/tmp/modules.dep`" = "/lib/modules/$MODTEST_UNAME/export_dep-$BITNESS.ko: /lib/modules/$MODTEST_UNAME/export_nodep-$BITNESS.ko" ]
[ "`grep -w noexport_dep-$BITNESS.ko: tests/tmp/modules.dep`" = "/lib/modules/$MODTEST_UNAME/noexport_dep-$BITNESS.ko: /lib/modules/$MODTEST_UNAME/export_nodep-$BITNESS.ko" ]
[ "`grep -w export_nodep-$BITNESS.ko: tests/tmp/modules.dep`" = "/lib/modules/$MODTEST_UNAME/export_nodep-$BITNESS.ko:" ]
[ "`grep -w noexport_nodep-$BITNESS.ko: tests/tmp/modules.dep`" = "/lib/modules/$MODTEST_UNAME/noexport_nodep-$BITNESS.ko:" ]
[ "`grep -w noexport_doubledep-$BITNESS.ko: tests/tmp/modules.dep`" = "/lib/modules/$MODTEST_UNAME/noexport_doubledep-$BITNESS.ko: /lib/modules/$MODTEST_UNAME/export_dep-$BITNESS.ko /lib/modules/$MODTEST_UNAME/export_nodep-$BITNESS.ko" ]

mv tests/tmp/modules.dep tests/tmp/modules.dep.old

# Synonyms
[ "`depmod -b /BASEDIR  -a`" = "" ]
diff -u tests/tmp/modules.dep.old tests/tmp/modules.dep
mv tests/tmp/modules.dep tests/tmp/modules.dep.old

[ "`depmod -b /BASEDIR -A`" = "" ]
diff -u tests/tmp/modules.dep.old tests/tmp/modules.dep
mv tests/tmp/modules.dep tests/tmp/modules.dep.old

[ "`depmod -b /BASEDIR -e -A`" = "" ]
diff -u tests/tmp/modules.dep.old tests/tmp/modules.dep
mv tests/tmp/modules.dep tests/tmp/modules.dep.old

[ "`depmod -b /BASEDIR -e -A $MODTEST_VERSION`" = "" ]
diff -u tests/tmp/modules.dep.old tests/tmp/modules.dep
mv tests/tmp/modules.dep tests/tmp/modules.dep.old

[ "`depmod --basedir /BASEDIR -e -A $MODTEST_VERSION 2>&1`" = "" ]
diff -u tests/tmp/modules.dep.old tests/tmp/modules.dep
mv tests/tmp/modules.dep tests/tmp/modules.dep.old

[ "`depmod --basedir=/BASEDIR -e -A $MODTEST_VERSION`" = "" ]
diff -u tests/tmp/modules.dep.old tests/tmp/modules.dep
mv tests/tmp/modules.dep tests/tmp/modules.dep.old

# Combined should form stdout versions.
grep -vh '^#' tests/tmp/modules.dep.old tests/tmp/modules.symbols > tests/tmp/modules.all.old

# Stdout versions.
depmod -b /BASEDIR -n | grep -v '^#' > tests/tmp/modules.all
diff -u tests/tmp/modules.all.old tests/tmp/modules.all
mv tests/tmp/modules.all tests/tmp/modules.all.old

depmod -b /BASEDIR -a -n | grep -v '^#' > tests/tmp/modules.all
diff -u tests/tmp/modules.all.old tests/tmp/modules.all
mv tests/tmp/modules.all tests/tmp/modules.all.old

depmod -b /BASEDIR -n -a $MODTEST_VERSION | grep -v '^#' > tests/tmp/modules.all
diff -u tests/tmp/modules.all.old tests/tmp/modules.all
mv tests/tmp/modules.all tests/tmp/modules.all.old

depmod -b /BASEDIR -e -n -A $MODTEST_VERSION | grep -v '^#' > tests/tmp/modules.all
diff -u tests/tmp/modules.all.old tests/tmp/modules.all
mv tests/tmp/modules.all tests/tmp/modules.all.old

done
done
