#! /bin/sh
# Test of generation of 32-bit and 64-bit maps, gzipped modules.

[ -n "$CONFIG_HAVE_ZLIB" ] || exit 0

for ENDIAN in -le -be; do
for BITNESS in 32 64; do

rm -rf tests/tmp/data
mkdir tests/tmp/data
for f in tests/data/$BITNESS$ENDIAN/map/*.ko; do
    gzip < $f > tests/tmp/data/`basename $f .ko`.ko.gz
done

# Inputs
MODTEST_OVERRIDE1=/lib/modules/$MODTEST_UNAME
MODTEST_OVERRIDE_WITH1=tests/tmp/data
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

MODTEST_OVERRIDE2=/lib/modules/$MODTEST_UNAME/ccw_map-$BITNESS.ko.gz
MODTEST_OVERRIDE_WITH2=tests/tmp/data/ccw_map-$BITNESS.ko.gz
export MODTEST_OVERRIDE2 MODTEST_OVERRIDE_WITH2

MODTEST_OVERRIDE3=/lib/modules/$MODTEST_UNAME/pci_map-$BITNESS.ko.gz
MODTEST_OVERRIDE_WITH3=tests/tmp/data/pci_map-$BITNESS.ko.gz
export MODTEST_OVERRIDE3 MODTEST_OVERRIDE_WITH3

MODTEST_OVERRIDE4=/lib/modules/$MODTEST_UNAME/usb_map-$BITNESS.ko.gz
MODTEST_OVERRIDE_WITH4=tests/tmp/data/usb_map-$BITNESS.ko.gz
export MODTEST_OVERRIDE4 MODTEST_OVERRIDE_WITH4

MODTEST_OVERRIDE5=/lib/modules/$MODTEST_UNAME/ieee1394_map-$BITNESS.ko.gz
MODTEST_OVERRIDE_WITH5=tests/tmp/data/ieee1394_map-$BITNESS.ko.gz
export MODTEST_OVERRIDE5 MODTEST_OVERRIDE_WITH5

MODTEST_OVERRIDE6=/lib/modules/$MODTEST_UNAME/pnp_map-$BITNESS.ko.gz
MODTEST_OVERRIDE_WITH6=tests/tmp/data/pnp_map-$BITNESS.ko.gz
export MODTEST_OVERRIDE6 MODTEST_OVERRIDE_WITH6

MODTEST_OVERRIDE25=/lib/modules/$MODTEST_UNAME/input_map-$BITNESS.ko.gz
MODTEST_OVERRIDE_WITH25=tests/tmp/data/input_map-$BITNESS.ko.gz
export MODTEST_OVERRIDE25 MODTEST_OVERRIDE_WITH25

MODTEST_OVERRIDE28=/lib/modules/$MODTEST_UNAME/of_map-$BITNESS.ko.gz
MODTEST_OVERRIDE_WITH28=tests/tmp/data/of_map-$BITNESS.ko.gz
export MODTEST_OVERRIDE28 MODTEST_OVERRIDE_WITH28

# Outputs
MODTEST_OVERRIDE7=/lib/modules/$MODTEST_UNAME/modules.dep
MODTEST_OVERRIDE_WITH7=tests/tmp/modules.dep
export MODTEST_OVERRIDE7 MODTEST_OVERRIDE_WITH7

MODTEST_OVERRIDE8=/lib/modules/$MODTEST_UNAME/modules.pcimap
MODTEST_OVERRIDE_WITH8=tests/tmp/modules.pcimap
export MODTEST_OVERRIDE8 MODTEST_OVERRIDE_WITH8

MODTEST_OVERRIDE9=/lib/modules/$MODTEST_UNAME/modules.usbmap
MODTEST_OVERRIDE_WITH9=tests/tmp/modules.usbmap
export MODTEST_OVERRIDE9 MODTEST_OVERRIDE_WITH9

MODTEST_OVERRIDE10=/lib/modules/$MODTEST_UNAME/modules.ccwmap
MODTEST_OVERRIDE_WITH10=tests/tmp/modules.ccwmap
export MODTEST_OVERRIDE10 MODTEST_OVERRIDE_WITH10

MODTEST_OVERRIDE11=/lib/modules/$MODTEST_UNAME/modules.alias
MODTEST_OVERRIDE_WITH11=tests/tmp/modules.alias
export MODTEST_OVERRIDE11 MODTEST_OVERRIDE_WITH11

MODTEST_OVERRIDE12=/lib/modules/$MODTEST_UNAME/modules.symbols
MODTEST_OVERRIDE_WITH12=tests/tmp/modules.symbols
export MODTEST_OVERRIDE12 MODTEST_OVERRIDE_WITH12

MODTEST_OVERRIDE13=/lib/modules/$MODTEST_UNAME/modules.ieee1394map
MODTEST_OVERRIDE_WITH13=tests/tmp/modules.ieee1394map
export MODTEST_OVERRIDE13 MODTEST_OVERRIDE_WITH13

MODTEST_OVERRIDE14=/lib/modules/$MODTEST_UNAME/modules.dep.temp
MODTEST_OVERRIDE_WITH14=tests/tmp/modules.dep.temp
export MODTEST_OVERRIDE14 MODTEST_OVERRIDE_WITH14

MODTEST_OVERRIDE15=/lib/modules/$MODTEST_UNAME/modules.pcimap.temp
MODTEST_OVERRIDE_WITH15=tests/tmp/modules.pcimap.temp
export MODTEST_OVERRIDE15 MODTEST_OVERRIDE_WITH15

MODTEST_OVERRIDE16=/lib/modules/$MODTEST_UNAME/modules.usbmap.temp
MODTEST_OVERRIDE_WITH16=tests/tmp/modules.usbmap.temp
export MODTEST_OVERRIDE16 MODTEST_OVERRIDE_WITH16

MODTEST_OVERRIDE17=/lib/modules/$MODTEST_UNAME/modules.ccwmap.temp
MODTEST_OVERRIDE_WITH17=tests/tmp/modules.ccwmap.temp
export MODTEST_OVERRIDE17 MODTEST_OVERRIDE_WITH17

MODTEST_OVERRIDE18=/lib/modules/$MODTEST_UNAME/modules.alias.temp
MODTEST_OVERRIDE_WITH18=tests/tmp/modules.alias.temp
export MODTEST_OVERRIDE18 MODTEST_OVERRIDE_WITH18

MODTEST_OVERRIDE19=/lib/modules/$MODTEST_UNAME/modules.symbols.temp
MODTEST_OVERRIDE_WITH19=tests/tmp/modules.symbols.temp
export MODTEST_OVERRIDE19 MODTEST_OVERRIDE_WITH19

MODTEST_OVERRIDE20=/lib/modules/$MODTEST_UNAME/modules.ieee1394map.temp
MODTEST_OVERRIDE_WITH20=tests/tmp/modules.ieee1394map.temp
export MODTEST_OVERRIDE20 MODTEST_OVERRIDE_WITH20

MODTEST_OVERRIDE21=/lib/modules/$MODTEST_UNAME/modules.isapnpmap.temp
MODTEST_OVERRIDE_WITH21=tests/tmp/modules.isapnpmap.temp
export MODTEST_OVERRIDE21 MODTEST_OVERRIDE_WITH21

MODTEST_OVERRIDE22=/lib/modules/$MODTEST_UNAME/modules.isapnpmap
MODTEST_OVERRIDE_WITH22=tests/tmp/modules.isapnpmap
export MODTEST_OVERRIDE22 MODTEST_OVERRIDE_WITH22

MODTEST_OVERRIDE23=/lib/modules/$MODTEST_UNAME/modules.inputmap.temp
MODTEST_OVERRIDE_WITH23=tests/tmp/modules.inputmap.temp
export MODTEST_OVERRIDE23 MODTEST_OVERRIDE_WITH23

MODTEST_OVERRIDE24=/lib/modules/$MODTEST_UNAME/modules.inputmap
MODTEST_OVERRIDE_WITH24=tests/tmp/modules.inputmap
export MODTEST_OVERRIDE24 MODTEST_OVERRIDE_WITH24

# FIXME: Test
MODTEST_OVERRIDE26=/lib/modules/$MODTEST_UNAME/modules.seriomap.temp
MODTEST_OVERRIDE_WITH26=tests/tmp/modules.seriomap.temp
export MODTEST_OVERRIDE26 MODTEST_OVERRIDE_WITH26

MODTEST_OVERRIDE27=/lib/modules/$MODTEST_UNAME/modules.seriomap
MODTEST_OVERRIDE_WITH27=tests/tmp/modules.seriomap
export MODTEST_OVERRIDE27 MODTEST_OVERRIDE_WITH27

MODTEST_OVERRIDE29=/lib/modules/$MODTEST_UNAME/modules.ofmap.temp
MODTEST_OVERRIDE_WITH29=tests/tmp/modules.ofmap.temp
export MODTEST_OVERRIDE29 MODTEST_OVERRIDE_WITH29

MODTEST_OVERRIDE30=/lib/modules/$MODTEST_UNAME/modules.ofmap
MODTEST_OVERRIDE_WITH30=tests/tmp/modules.ofmap
export MODTEST_OVERRIDE30 MODTEST_OVERRIDE_WITH30

# Expect no output.
[ "`depmod`" = "" ]

# Check PCI: expect 2 lines
[ `grep -vc '^#' < tests/tmp/modules.pcimap` = 2 ]

[ "`grep pci_map tests/tmp/modules.pcimap`" = "pci_map-$BITNESS           0x00000001 0x00000002 0x00000003 0x00000004 0x00000005 0x00000006 0x0
pci_map-$BITNESS           0x0000000b 0x0000000c 0x0000000d 0x0000000e 0x0000000f 0x00000010 0x0" ]

# Check USB: expect 2 lines
[ `grep -vc '^#' < tests/tmp/modules.usbmap` = 2 ]

[ "`grep usb_map tests/tmp/modules.usbmap`" = "usb_map-$BITNESS           0x0001      0x0002   0x0003    0x0004       0x0005       0x06         0x07            0x08            0x09            0x0a               0x0b               0x0
usb_map-$BITNESS           0x000b      0x000c   0x000d    0x000e       0x000f       0x10         0x11            0x12            0x13            0x14               0x15               0x0" ]

# Check CCW: expect 2 lines
[ `grep -vc '^#' < tests/tmp/modules.ccwmap` = 2 ]

[ "`grep ccw_map tests/tmp/modules.ccwmap`" = "ccw_map-$BITNESS           0x000f      0x0001  0x03      0x0002  0x04
ccw_map-$BITNESS           0x000f      0x000b  0x0d      0x000c  0x0e" ]

# Check ieee1394: expect 2 lines
[ `grep -vc '^#' < tests/tmp/modules.ieee1394map` = 2 ]

#%-20s 0x%08x  0x%06x  0x%06x 0x%06x     0x%06x\n",
#+		name, fw->match_flags, fw->vendor_id, fw->model_id,
#+		fw->specifier_id, fw->version);
[ "`grep ieee1394_map tests/tmp/modules.ieee1394map`" = "ieee1394_map-$BITNESS      0x0000000c  0x000000  0x000000 0x00a02d     0x010001
ieee1394_map-$BITNESS      0x0000000c  0x000000  0x000000 0x00a02d     0x000100" ]

# Check input: expect 2 lines
[ `grep -vc '^#' < tests/tmp/modules.inputmap` = 2 ]

# module         matchBits bustype vendor product version evBits keyBits relBits absBits mscBits ledBits sndBits ffBits driver_info
[ "`grep input_map tests/tmp/modules.inputmap`" = "input_map-$BITNESS        0x10  0x0  0x0  0x0  0x0  2  0  0  0  0  0  0  0  0x0
input_map-$BITNESS        0x10  0x0  0x0  0x0  0x0  40000  0  0  0  0  0  0  0  0x0" ]

# Check of: expect 7 lines
[ `grep -vc '^#' < tests/tmp/modules.ofmap` = 7 ]

# of module          name                 type                 compatible
[ "`grep of_map tests/tmp/modules.ofmap`" = "of_map-$BITNESS            test_name_1          *                    *
of_map-$BITNESS            *                    test_type_1          *
of_map-$BITNESS            *                    *                    test_compat_1
of_map-$BITNESS            test_name_2          test_type_2          *
of_map-$BITNESS            test_name_3          *                    test_compat_2
of_map-$BITNESS            *                    test_type_3          test_compat_3
of_map-$BITNESS            test_name_4          test_type_4          test_compat_4" ]

mv tests/tmp/modules.dep tests/tmp/modules.dep.old
mv tests/tmp/modules.pcimap tests/tmp/modules.pcimap.old
mv tests/tmp/modules.usbmap tests/tmp/modules.usbmap.old
mv tests/tmp/modules.ccwmap tests/tmp/modules.ccwmap.old
mv tests/tmp/modules.ieee1394map tests/tmp/modules.ieee1394map.old
mv tests/tmp/modules.isapnpmap tests/tmp/modules.isapnpmap.old
mv tests/tmp/modules.inputmap tests/tmp/modules.inputmap.old
mv tests/tmp/modules.ofmap tests/tmp/modules.ofmap.old

# Synonyms
[ "`depmod -a`" = "" ]
diff -u tests/tmp/modules.dep.old tests/tmp/modules.dep
diff -u tests/tmp/modules.pcimap.old tests/tmp/modules.pcimap
diff -u tests/tmp/modules.usbmap.old tests/tmp/modules.usbmap
diff -u tests/tmp/modules.ccwmap.old tests/tmp/modules.ccwmap
diff -u tests/tmp/modules.ieee1394map.old tests/tmp/modules.ieee1394map
diff -u tests/tmp/modules.isapnpmap.old tests/tmp/modules.isapnpmap
diff -u tests/tmp/modules.inputmap.old tests/tmp/modules.inputmap
diff -u tests/tmp/modules.ofmap.old tests/tmp/modules.ofmap

[ "`depmod -A`" = "" ]
diff -u tests/tmp/modules.dep.old tests/tmp/modules.dep
diff -u tests/tmp/modules.pcimap.old tests/tmp/modules.pcimap
diff -u tests/tmp/modules.usbmap.old tests/tmp/modules.usbmap
diff -u tests/tmp/modules.ccwmap.old tests/tmp/modules.ccwmap
diff -u tests/tmp/modules.ieee1394map.old tests/tmp/modules.ieee1394map
diff -u tests/tmp/modules.isapnpmap.old tests/tmp/modules.isapnpmap
diff -u tests/tmp/modules.inputmap.old tests/tmp/modules.inputmap
diff -u tests/tmp/modules.ofmap.old tests/tmp/modules.ofmap

[ "`depmod -e -A`" = "" ]
diff -u tests/tmp/modules.dep.old tests/tmp/modules.dep
diff -u tests/tmp/modules.pcimap.old tests/tmp/modules.pcimap
diff -u tests/tmp/modules.usbmap.old tests/tmp/modules.usbmap
diff -u tests/tmp/modules.ccwmap.old tests/tmp/modules.ccwmap
diff -u tests/tmp/modules.ieee1394map.old tests/tmp/modules.ieee1394map
diff -u tests/tmp/modules.isapnpmap.old tests/tmp/modules.isapnpmap
diff -u tests/tmp/modules.inputmap.old tests/tmp/modules.inputmap
diff -u tests/tmp/modules.ofmap.old tests/tmp/modules.ofmap

[ "`depmod -e -A $MODTEST_VERSION`" = "" ]
diff -u tests/tmp/modules.dep.old tests/tmp/modules.dep
diff -u tests/tmp/modules.pcimap.old tests/tmp/modules.pcimap
diff -u tests/tmp/modules.usbmap.old tests/tmp/modules.usbmap
diff -u tests/tmp/modules.ccwmap.old tests/tmp/modules.ccwmap
diff -u tests/tmp/modules.ieee1394map.old tests/tmp/modules.ieee1394map
diff -u tests/tmp/modules.isapnpmap.old tests/tmp/modules.isapnpmap
diff -u tests/tmp/modules.inputmap.old tests/tmp/modules.inputmap
diff -u tests/tmp/modules.ofmap.old tests/tmp/modules.ofmap

# We expect the same from -n.
grep -hv '^#' tests/tmp/modules.dep.old tests/tmp/modules.pcimap.old tests/tmp/modules.usbmap.old tests/tmp/modules.ccwmap.old tests/tmp/modules.ieee1394map.old tests/tmp/modules.isapnpmap.old tests/tmp/modules.inputmap.old tests/tmp/modules.ofmap.old > tests/tmp/out

# Stdout versions.
depmod -n | grep -v '^#' > tests/tmp/stdout
diff -u tests/tmp/out tests/tmp/stdout

depmod -a -n | grep -v '^#' > tests/tmp/modules.dep
diff -u tests/tmp/out tests/tmp/stdout

depmod -n -a $MODTEST_VERSION | grep -v '^#' > tests/tmp/modules.dep
diff -u tests/tmp/out tests/tmp/stdout

depmod -e -n -A $MODTEST_VERSION | grep -v '^#' > tests/tmp/modules.dep
diff -u tests/tmp/out tests/tmp/stdout

done
done
