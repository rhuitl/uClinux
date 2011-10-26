#! /bin/sh
# Test module dependencies.

for BITNESS in 32 64; do

# Inputs
MODTEST_OVERRIDE1=/lib/modules/$MODTEST_UNAME
MODTEST_OVERRIDE_WITH1=tests/data/$BITNESS/normal
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

MODTEST_OVERRIDE2=/lib/modules/$MODTEST_UNAME/export_dep-$BITNESS.ko
MODTEST_OVERRIDE_WITH2=tests/data/$BITNESS/normal/export_dep-$BITNESS.ko
export MODTEST_OVERRIDE2 MODTEST_OVERRIDE_WITH2

MODTEST_OVERRIDE3=/lib/modules/$MODTEST_UNAME/noexport_dep-$BITNESS.ko
MODTEST_OVERRIDE_WITH3=tests/data/$BITNESS/normal/noexport_dep-$BITNESS.ko
export MODTEST_OVERRIDE3 MODTEST_OVERRIDE_WITH3

MODTEST_OVERRIDE4=/lib/modules/$MODTEST_UNAME/noexport_nodep-$BITNESS.ko
MODTEST_OVERRIDE_WITH4=tests/data/$BITNESS/normal/noexport_nodep-$BITNESS.ko
export MODTEST_OVERRIDE4 MODTEST_OVERRIDE_WITH4

MODTEST_OVERRIDE5=/lib/modules/$MODTEST_UNAME/export_nodep-$BITNESS.ko
MODTEST_OVERRIDE_WITH5=tests/data/$BITNESS/normal/export_nodep-$BITNESS.ko
export MODTEST_OVERRIDE5 MODTEST_OVERRIDE_WITH5

MODTEST_OVERRIDE6=/lib/modules/$MODTEST_UNAME/noexport_doubledep-$BITNESS.ko
MODTEST_OVERRIDE_WITH6=tests/data/$BITNESS/normal/noexport_doubledep-$BITNESS.ko
export MODTEST_OVERRIDE6 MODTEST_OVERRIDE_WITH6

MODTEST_OVERRIDE7=/lib/modules/$MODTEST_UNAME/modules.dep
MODTEST_OVERRIDE_WITH7=tests/tmp/modules.dep
export MODTEST_OVERRIDE7 MODTEST_OVERRIDE_WITH7

MODTEST_OVERRIDE8=/etc/modprobe.conf
MODTEST_OVERRIDE_WITH8=tests/tmp/modprobe.conf
export MODTEST_OVERRIDE8 MODTEST_OVERRIDE_WITH8

MODTEST_OVERRIDE9=/lib/modules/$MODTEST_UNAME/modules.dep
MODTEST_OVERRIDE_WITH9=tests/tmp/modules.dep
export MODTEST_OVERRIDE9 MODTEST_OVERRIDE_WITH9

MODTEST_OVERRIDE10=/proc/modules
MODTEST_OVERRIDE_WITH10=tests/tmp/proc
export MODTEST_OVERRIDE10 MODTEST_OVERRIDE_WITH10

# Now create modules.dep
cat > tests/tmp/modules.dep <<EOF
# Should handle comments.
/lib/modules/2.5.52/noexport_nodep-$BITNESS.ko:
/lib/modules/2.5.52/noexport_doubledep-$BITNESS.ko: /lib/modules/2.5.52/export_dep-$BITNESS.ko /lib/modules/2.5.52/export_nodep-$BITNESS.ko
/lib/modules/2.5.52/noexport_dep-$BITNESS.ko: /lib/modules/2.5.52/export_nodep-$BITNESS.ko
/lib/modules/2.5.52/export_nodep-$BITNESS.ko:
/lib/modules/2.5.52/export_dep-$BITNESS.ko: /lib/modules/2.5.52/export_nodep-$BITNESS.ko
EOF

# Insertion
# Empty proc
touch tests/tmp/proc

[ "`modprobe -v -n noexport_nodep-$BITNESS 2>&1`" = "insmod /lib/modules/2.5.52/noexport_nodep-$BITNESS.ko " ]
[ "`modprobe -v -n noexport_nodep-$BITNESS OPTIONS 2>&1`" = "insmod /lib/modules/2.5.52/noexport_nodep-$BITNESS.ko OPTIONS" ]

[ "`modprobe -v -n export_nodep-$BITNESS 2>&1`" = "insmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko " ]
[ "`modprobe -v -n export_nodep-$BITNESS OPTIONS 2>&1`" = "insmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko OPTIONS" ]

[ "`modprobe -v -n noexport_dep-$BITNESS 2>&1`" = "insmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko 
insmod /lib/modules/2.5.52/noexport_dep-$BITNESS.ko " ]
[ "`modprobe -v -n noexport_dep-$BITNESS OPTIONS 2>&1`" = "insmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko 
insmod /lib/modules/2.5.52/noexport_dep-$BITNESS.ko OPTIONS" ]

[ "`modprobe -v -n export_dep-$BITNESS 2>&1`" = "insmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko 
insmod /lib/modules/2.5.52/export_dep-$BITNESS.ko " ]
[ "`modprobe -v -n export_dep-$BITNESS OPTIONS 2>&1`" = "insmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko 
insmod /lib/modules/2.5.52/export_dep-$BITNESS.ko OPTIONS" ]

[ "`modprobe -v -n noexport_doubledep-$BITNESS 2>&1`" = "insmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko 
insmod /lib/modules/2.5.52/export_dep-$BITNESS.ko 
insmod /lib/modules/2.5.52/noexport_doubledep-$BITNESS.ko " ]
[ "`modprobe -v -n noexport_doubledep-$BITNESS OPTIONS 2>&1`" = "insmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko 
insmod /lib/modules/2.5.52/export_dep-$BITNESS.ko 
insmod /lib/modules/2.5.52/noexport_doubledep-$BITNESS.ko OPTIONS" ]

# Test alias and options resolution
echo "alias foo noexport_doubledep-$BITNESS" > tests/tmp/modprobe.conf
echo "options noexport_doubledep-$BITNESS OPTIONS" >> tests/tmp/modprobe.conf
[ "`modprobe -v -n foo 2>&1`" = "insmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko 
insmod /lib/modules/2.5.52/export_dep-$BITNESS.ko 
insmod /lib/modules/2.5.52/noexport_doubledep-$BITNESS.ko OPTIONS" ]

# All in proc
cat > tests/tmp/proc <<EOF
noexport_nodep_$BITNESS 100 0 -
export_nodep_$BITNESS 100 0 -
noexport_dep_$BITNESS 100 0 export_nodep_$BITNESS,
export_dep_$BITNESS 100 0 export_nodep_$BITNESS,
noexport_doubledep_$BITNESS 100 0 export_dep_$BITNESS,export_nodep_$BITNESS
EOF

# Removal
[ "`modprobe -v -n -r noexport_nodep-$BITNESS 2>&1`" = "rmmod /lib/modules/2.5.52/noexport_nodep-$BITNESS.ko" ]
[ "`modprobe -v -n -r export_nodep-$BITNESS 2>&1`" = "rmmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko" ]
[ "`modprobe -v -n -r noexport_dep-$BITNESS 2>&1`" = "rmmod /lib/modules/2.5.52/noexport_dep-$BITNESS.ko
rmmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko" ]
[ "`modprobe -v -n -r export_dep-$BITNESS 2>&1`" = "rmmod /lib/modules/2.5.52/export_dep-$BITNESS.ko
rmmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko" ]
[ "`modprobe -v -n -r noexport_doubledep-$BITNESS 2>&1`" = "rmmod /lib/modules/2.5.52/noexport_doubledep-$BITNESS.ko
rmmod /lib/modules/2.5.52/export_dep-$BITNESS.ko
rmmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko" ]

done
