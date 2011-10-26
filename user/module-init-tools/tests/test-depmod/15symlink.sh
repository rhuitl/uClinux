#! /bin/sh
# Test that we ignore symlinks.

for ENDIAN in -le -be; do
for BITNESS in 32 64; do

# Inputs
MODTEST_OVERRIDE1=/lib/modules/$MODTEST_UNAME
MODTEST_OVERRIDE_WITH1=tests/tmp/modules
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

MODTEST_OVERRIDE2=/lib/modules/$MODTEST_UNAME/kernel/export_dep-$BITNESS.ko
MODTEST_OVERRIDE_WITH2=tests/tmp/modules/kernel/export_dep-$BITNESS.ko
export MODTEST_OVERRIDE2 MODTEST_OVERRIDE_WITH2

MODTEST_OVERRIDE3=/lib/modules/$MODTEST_UNAME/kernel/noexport_dep-$BITNESS.ko
MODTEST_OVERRIDE_WITH3=tests/tmp/modules/kernel/noexport_dep-$BITNESS.ko
export MODTEST_OVERRIDE3 MODTEST_OVERRIDE_WITH3

MODTEST_OVERRIDE4=/lib/modules/$MODTEST_UNAME/kernel/noexport_nodep-$BITNESS.ko
MODTEST_OVERRIDE_WITH4=tests/tmp/modules/kernel/noexport_nodep-$BITNESS.ko
export MODTEST_OVERRIDE4 MODTEST_OVERRIDE_WITH4

MODTEST_OVERRIDE5=/lib/modules/$MODTEST_UNAME/kernel/export_nodep-$BITNESS.ko
MODTEST_OVERRIDE_WITH5=tests/tmp/modules/kernel/export_nodep-$BITNESS.ko
export MODTEST_OVERRIDE5 MODTEST_OVERRIDE_WITH5

MODTEST_OVERRIDE6=/lib/modules/$MODTEST_UNAME/kernel/noexport_doubledep-$BITNESS.ko
MODTEST_OVERRIDE_WITH6=tests/tmp/modules/kernel/noexport_doubledep-$BITNESS.ko
export MODTEST_OVERRIDE6 MODTEST_OVERRIDE_WITH6

# Outputs
MODTEST_OVERRIDE7=/lib/modules/$MODTEST_UNAME/modules.dep
MODTEST_OVERRIDE_WITH7=tests/tmp/modules/modules.dep
export MODTEST_OVERRIDE7 MODTEST_OVERRIDE_WITH7

MODTEST_OVERRIDE8=/lib/modules/$MODTEST_UNAME/modules.pcimap
MODTEST_OVERRIDE_WITH8=tests/tmp/modules/modules.pcimap
export MODTEST_OVERRIDE8 MODTEST_OVERRIDE_WITH8

MODTEST_OVERRIDE9=/lib/modules/$MODTEST_UNAME/modules.usbmap
MODTEST_OVERRIDE_WITH9=tests/tmp/modules/modules.usbmap
export MODTEST_OVERRIDE9 MODTEST_OVERRIDE_WITH9

MODTEST_OVERRIDE10=/lib/modules/$MODTEST_UNAME/modules.ccwmap
MODTEST_OVERRIDE_WITH10=tests/tmp/modules/modules.ccwmap
export MODTEST_OVERRIDE10 MODTEST_OVERRIDE_WITH10

MODTEST_OVERRIDE11=/lib/modules/$MODTEST_UNAME/modules.alias
MODTEST_OVERRIDE_WITH11=tests/tmp/modules/modules.alias
export MODTEST_OVERRIDE11 MODTEST_OVERRIDE_WITH11

MODTEST_OVERRIDE12=/lib/modules/$MODTEST_UNAME/modules.symbols
MODTEST_OVERRIDE_WITH12=tests/tmp/modules/modules.symbols
export MODTEST_OVERRIDE12 MODTEST_OVERRIDE_WITH12

MODTEST_OVERRIDE13=/lib/modules/$MODTEST_UNAME/modules.ieee1394map
MODTEST_OVERRIDE_WITH13=tests/tmp/modules/modules.ieee1394map
export MODTEST_OVERRIDE13 MODTEST_OVERRIDE_WITH13

MODTEST_OVERRIDE14=/lib/modules/$MODTEST_UNAME/modules.dep.temp
MODTEST_OVERRIDE_WITH14=tests/tmp/modules/modules.dep.temp
export MODTEST_OVERRIDE14 MODTEST_OVERRIDE_WITH14

MODTEST_OVERRIDE15=/lib/modules/$MODTEST_UNAME/modules.pcimap.temp
MODTEST_OVERRIDE_WITH15=tests/tmp/modules/modules.pcimap.temp
export MODTEST_OVERRIDE15 MODTEST_OVERRIDE_WITH15

MODTEST_OVERRIDE16=/lib/modules/$MODTEST_UNAME/modules.usbmap.temp
MODTEST_OVERRIDE_WITH16=tests/tmp/modules/modules.usbmap.temp
export MODTEST_OVERRIDE16 MODTEST_OVERRIDE_WITH16

MODTEST_OVERRIDE17=/lib/modules/$MODTEST_UNAME/modules.ccwmap.temp
MODTEST_OVERRIDE_WITH17=tests/tmp/modules/modules.ccwmap.temp
export MODTEST_OVERRIDE17 MODTEST_OVERRIDE_WITH17

MODTEST_OVERRIDE18=/lib/modules/$MODTEST_UNAME/modules.alias.temp
MODTEST_OVERRIDE_WITH18=tests/tmp/modules/modules.alias.temp
export MODTEST_OVERRIDE18 MODTEST_OVERRIDE_WITH18

MODTEST_OVERRIDE19=/lib/modules/$MODTEST_UNAME/modules.symbols.temp
MODTEST_OVERRIDE_WITH19=tests/tmp/modules/modules.symbols.temp
export MODTEST_OVERRIDE19 MODTEST_OVERRIDE_WITH19

MODTEST_OVERRIDE20=/lib/modules/$MODTEST_UNAME/modules.ieee1394map.temp
MODTEST_OVERRIDE_WITH20=tests/tmp/modules/modules.ieee1394map.temp
export MODTEST_OVERRIDE20 MODTEST_OVERRIDE_WITH20

MODTEST_OVERRIDE21=/lib/modules/$MODTEST_UNAME/modules.isapnpmap.temp
MODTEST_OVERRIDE_WITH21=tests/tmp/modules/modules.isapnpmap.temp
export MODTEST_OVERRIDE21 MODTEST_OVERRIDE_WITH21

MODTEST_OVERRIDE22=/lib/modules/$MODTEST_UNAME/modules.isapnpmap
MODTEST_OVERRIDE_WITH22=tests/tmp/modules/modules.isapnpmap
export MODTEST_OVERRIDE22 MODTEST_OVERRIDE_WITH22

MODTEST_OVERRIDE23=/lib/modules/$MODTEST_UNAME/modules.inputmap.temp
MODTEST_OVERRIDE_WITH23=tests/tmp/modules/modules.inputmap.temp
export MODTEST_OVERRIDE23 MODTEST_OVERRIDE_WITH23

MODTEST_OVERRIDE24=/lib/modules/$MODTEST_UNAME/modules.inputmap
MODTEST_OVERRIDE_WITH24=tests/tmp/modules/modules.inputmap
export MODTEST_OVERRIDE24 MODTEST_OVERRIDE_WITH24

MODTEST_OVERRIDE25=/lib/modules/$MODTEST_UNAME/modules.seriomap.temp
MODTEST_OVERRIDE_WITH25=tests/tmp/modules.seriomap.temp
export MODTEST_OVERRIDE25 MODTEST_OVERRIDE_WITH25

MODTEST_OVERRIDE26=/lib/modules/$MODTEST_UNAME/modules.seriomap
MODTEST_OVERRIDE_WITH26=tests/tmp/modules.seriomap
export MODTEST_OVERRIDE26 MODTEST_OVERRIDE_WITH26

MODTEST_OVERRIDE31=/lib/modules/$MODTEST_UNAME/modules.ofmap.temp
MODTEST_OVERRIDE_WITH31=tests/tmp/modules.ofmap.temp
export MODTEST_OVERRIDE31 MODTEST_OVERRIDE_WITH31

MODTEST_OVERRIDE32=/lib/modules/$MODTEST_UNAME/modules.ofmap
MODTEST_OVERRIDE_WITH32=tests/tmp/modules.ofmap
export MODTEST_OVERRIDE32 MODTEST_OVERRIDE_WITH32

# More inputs
MODTEST_OVERRIDE27=/lib/modules/$MODTEST_UNAME/build
MODTEST_OVERRIDE_WITH27=tests/tmp/modules/build
export MODTEST_OVERRIDE27 MODTEST_OVERRIDE_WITH27

MODTEST_OVERRIDE28=/lib/modules/$MODTEST_UNAME/kernel
MODTEST_OVERRIDE_WITH28=tests/tmp/modules/kernel
export MODTEST_OVERRIDE28 MODTEST_OVERRIDE_WITH28

MODTEST_OVERRIDE29=/lib/modules/$MODTEST_UNAME/updates
MODTEST_OVERRIDE_WITH29=tests/tmp/updates
export MODTEST_OVERRIDE29 MODTEST_OVERRIDE_WITH29

MODTEST_OVERRIDE30=/lib/modules/$MODTEST_UNAME/updates/rename-new-$BITNESS.ko
MODTEST_OVERRIDE_WITH30=tests/tmp/updates/rename-new-$BITNESS.ko
export MODTEST_OVERRIDE30 MODTEST_OVERRIDE_WITH30

mkdir tests/tmp/nogo tests/tmp/updates tests/tmp/modules
mkdir tests/tmp/modules/kernel
cp tests/data/$BITNESS$ENDIAN/normal/*.ko tests/tmp/modules/kernel

# Should not find this through symlink
ln -s ../nogo tests/tmp/modules/build
cp tests/data/$BITNESS$ENDIAN/alias/alias-$BITNESS.ko tests/tmp/nogo

# SHOULD go through updates symlink (SuSE want shared updates)
ln -s ../updates tests/tmp/modules/updates
cp tests/data/$BITNESS$ENDIAN/rename/rename-new-$BITNESS.ko tests/tmp/updates

# Expect no output.
[ "`depmod 2>&1`" = "" ]

# Check modules.dep results: expect 6 lines
[ `grep -vc '^#' < tests/tmp/modules/modules.dep` = 6 ]

[ "`grep -w export_dep-$BITNESS.ko: tests/tmp/modules/modules.dep`" = "/lib/modules/$MODTEST_UNAME/kernel/export_dep-$BITNESS.ko: /lib/modules/$MODTEST_UNAME/kernel/export_nodep-$BITNESS.ko" ]
[ "`grep -w noexport_dep-$BITNESS.ko: tests/tmp/modules/modules.dep`" = "/lib/modules/$MODTEST_UNAME/kernel/noexport_dep-$BITNESS.ko: /lib/modules/$MODTEST_UNAME/kernel/export_nodep-$BITNESS.ko" ]
[ "`grep -w noexport_nodep-$BITNESS.ko: tests/tmp/modules/modules.dep`" = "/lib/modules/$MODTEST_UNAME/kernel/noexport_nodep-$BITNESS.ko:" ]
[ "`grep -w noexport_doubledep-$BITNESS.ko: tests/tmp/modules/modules.dep`" = "/lib/modules/$MODTEST_UNAME/kernel/noexport_doubledep-$BITNESS.ko: /lib/modules/$MODTEST_UNAME/kernel/export_dep-$BITNESS.ko /lib/modules/$MODTEST_UNAME/kernel/export_nodep-$BITNESS.ko" ]
[ "`grep -w export_nodep-$BITNESS.ko: tests/tmp/modules/modules.dep`" = "/lib/modules/$MODTEST_UNAME/kernel/export_nodep-$BITNESS.ko:" ]
[ "`grep -w rename-new-$BITNESS.ko: tests/tmp/modules/modules.dep`" = "/lib/modules/$MODTEST_UNAME/updates/rename-new-$BITNESS.ko:" ]

# Check modules.symbols results: expect 3 lines
[ `grep -vc '^#' < tests/tmp/modules/modules.symbols` = 3 ]

[ "`grep -w symbol:exported1 tests/tmp/modules/modules.symbols`" = "alias symbol:exported1 export_nodep_$BITNESS" ]
[ "`grep -w symbol:exported2 tests/tmp/modules/modules.symbols`" = "alias symbol:exported2 export_nodep_$BITNESS" ]
[ "`grep -w symbol:exported3 tests/tmp/modules/modules.symbols`" = "alias symbol:exported3 export_dep_$BITNESS" ]

mv tests/tmp/modules/modules.dep tests/tmp/modules/modules.dep.old
mv tests/tmp/modules/modules.symbols tests/tmp/modules/modules.symbols.old

# Synonyms
[ "`depmod $MODTEST_UNAME`" = "" ]
diff -u tests/tmp/modules/modules.dep.old tests/tmp/modules/modules.dep >/dev/null
mv tests/tmp/modules/modules.dep tests/tmp/modules/modules.dep.old
diff -u tests/tmp/modules/modules.symbols.old tests/tmp/modules/modules.symbols >/dev/null
mv tests/tmp/modules/modules.symbols tests/tmp/modules/modules.symbols.old

[ "`depmod -a`" = "" ]
diff -u tests/tmp/modules/modules.dep.old tests/tmp/modules/modules.dep >/dev/null
mv tests/tmp/modules/modules.dep tests/tmp/modules/modules.dep.old
diff -u tests/tmp/modules/modules.symbols.old tests/tmp/modules/modules.symbols >/dev/null
mv tests/tmp/modules/modules.symbols tests/tmp/modules/modules.symbols.old

[ "`depmod -a $MODTEST_UNAME`" = "" ]
diff -u tests/tmp/modules/modules.dep.old tests/tmp/modules/modules.dep >/dev/null
mv tests/tmp/modules/modules.dep tests/tmp/modules/modules.dep.old
diff -u tests/tmp/modules/modules.symbols.old tests/tmp/modules/modules.symbols >/dev/null
mv tests/tmp/modules/modules.symbols tests/tmp/modules/modules.symbols.old

[ "`depmod -A`" = "" ]
diff -u tests/tmp/modules/modules.dep.old tests/tmp/modules/modules.dep >/dev/null
mv tests/tmp/modules/modules.dep tests/tmp/modules/modules.dep.old
diff -u tests/tmp/modules/modules.symbols.old tests/tmp/modules/modules.symbols >/dev/null
mv tests/tmp/modules/modules.symbols tests/tmp/modules/modules.symbols.old

[ "`depmod -A $MODTEST_UNAME`" = "" ]
diff -u tests/tmp/modules/modules.dep.old tests/tmp/modules/modules.dep >/dev/null
mv tests/tmp/modules/modules.dep tests/tmp/modules/modules.dep.old
diff -u tests/tmp/modules/modules.symbols.old tests/tmp/modules/modules.symbols >/dev/null
mv tests/tmp/modules/modules.symbols tests/tmp/modules/modules.symbols.old

[ "`depmod -e -A`" = "" ]
diff -u tests/tmp/modules/modules.dep.old tests/tmp/modules/modules.dep >/dev/null
mv tests/tmp/modules/modules.dep tests/tmp/modules/modules.dep.old
diff -u tests/tmp/modules/modules.symbols.old tests/tmp/modules/modules.symbols >/dev/null
mv tests/tmp/modules/modules.symbols tests/tmp/modules/modules.symbols.old

[ "`depmod -e -A $MODTEST_VERSION`" = "" ]
diff -u tests/tmp/modules/modules.dep.old tests/tmp/modules/modules.dep >/dev/null
mv tests/tmp/modules/modules.dep tests/tmp/modules/modules.dep.old
diff -u tests/tmp/modules/modules.symbols.old tests/tmp/modules/modules.symbols >/dev/null
mv tests/tmp/modules/modules.symbols tests/tmp/modules/modules.symbols.old

[ "`depmod --all`" = "" ]
diff -u tests/tmp/modules/modules.dep.old tests/tmp/modules/modules.dep >/dev/null
mv tests/tmp/modules/modules.dep tests/tmp/modules/modules.dep.old
diff -u tests/tmp/modules/modules.symbols.old tests/tmp/modules/modules.symbols >/dev/null
mv tests/tmp/modules/modules.symbols tests/tmp/modules/modules.symbols.old

[ "`depmod --quick`" = "" ]
diff -u tests/tmp/modules/modules.dep.old tests/tmp/modules/modules.dep >/dev/null
mv tests/tmp/modules/modules.dep tests/tmp/modules/modules.dep.old
diff -u tests/tmp/modules/modules.symbols.old tests/tmp/modules/modules.symbols >/dev/null
mv tests/tmp/modules/modules.symbols tests/tmp/modules/modules.symbols.old

[ "`depmod -e --quick`" = "" ]
diff -u tests/tmp/modules/modules.dep.old tests/tmp/modules/modules.dep >/dev/null
mv tests/tmp/modules/modules.dep tests/tmp/modules/modules.dep.old
diff -u tests/tmp/modules/modules.symbols.old tests/tmp/modules/modules.symbols >/dev/null
mv tests/tmp/modules/modules.symbols tests/tmp/modules/modules.symbols.old

[ "`depmod -e --quick $MODTEST_VERSION`" = "" ]
diff -u tests/tmp/modules/modules.dep.old tests/tmp/modules/modules.dep >/dev/null
mv tests/tmp/modules/modules.dep tests/tmp/modules/modules.dep.old
diff -u tests/tmp/modules/modules.symbols.old tests/tmp/modules/modules.symbols >/dev/null
mv tests/tmp/modules/modules.symbols tests/tmp/modules/modules.symbols.old

[ "`depmod --errsyms --quick`" = "" ]
diff -u tests/tmp/modules/modules.dep.old tests/tmp/modules/modules.dep >/dev/null
mv tests/tmp/modules/modules.dep tests/tmp/modules/modules.dep.old
diff -u tests/tmp/modules/modules.symbols.old tests/tmp/modules/modules.symbols >/dev/null
mv tests/tmp/modules/modules.symbols tests/tmp/modules/modules.symbols.old

[ "`depmod --errsyms --quick $MODTEST_VERSION`" = "" ]
diff -u tests/tmp/modules/modules.dep.old tests/tmp/modules/modules.dep >/dev/null
mv tests/tmp/modules/modules.dep tests/tmp/modules/modules.dep.old
diff -u tests/tmp/modules/modules.symbols.old tests/tmp/modules/modules.symbols >/dev/null
mv tests/tmp/modules/modules.symbols tests/tmp/modules/modules.symbols.old

# Combined should form stdout versions.
grep -vh '^#' tests/tmp/modules/modules.dep.old tests/tmp/modules/modules.symbols.old > tests/tmp/modules/modules.all.old

# Stdout versions.
depmod -n | grep -v '^#' > tests/tmp/modules/modules.all
diff -u tests/tmp/modules/modules.all.old tests/tmp/modules/modules.all >/dev/null
mv tests/tmp/modules/modules.all tests/tmp/modules/modules.all.old

depmod -a -n | grep -v '^#' > tests/tmp/modules/modules.all
diff -u tests/tmp/modules/modules.all.old tests/tmp/modules/modules.all >/dev/null
mv tests/tmp/modules/modules.all tests/tmp/modules/modules.all.old

depmod -n -a $MODTEST_VERSION | grep -v '^#' > tests/tmp/modules/modules.all
diff -u tests/tmp/modules/modules.all.old tests/tmp/modules/modules.all >/dev/null
mv tests/tmp/modules/modules.all tests/tmp/modules/modules.all.old

depmod -e -n -A $MODTEST_VERSION | grep -v '^#' > tests/tmp/modules/modules.all
diff -u tests/tmp/modules/modules.all.old tests/tmp/modules/modules.all >/dev/null
mv tests/tmp/modules/modules.all tests/tmp/modules/modules.all.old

rm -rf tests/tmp/*
done # 32/64-bit
done
