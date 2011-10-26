#! /bin/sh

# If A depends on B and C, and B is installed, C still needs to be installed!
# (Bug in 3.0-pre6 & 3.0-pre7).

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
MODTEST_OVERRIDE_WITH8=FILE-WHICH-DOESNT-EXIST
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
/lib/modules/2.5.52/noexport_doubledep-$BITNESS.ko: /lib/modules/2.5.52/export_dep-$BITNESS.ko /lib/modules/2.5.52/export_nodep-$BITNESS.ko
EOF

# Now, export-dep is in proc (actually this can't happen, since it depends
# on export_nodep, but this is to test).
cat > tests/tmp/proc <<EOF
export_dep_$BITNESS 100 0 ,
EOF

SIZE_EXPORT_NODEP=$(echo `wc -c < tests/data/$BITNESS/normal/export_nodep-$BITNESS.ko`)
SIZE_NOEXPORT_DOUBLEDEP=$(echo `wc -c < tests/data/$BITNESS/normal/noexport_doubledep-$BITNESS.ko`)

[ "`modprobe -v noexport_doubledep-$BITNESS 2>&1`" = "insmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko 
INIT_MODULE: $SIZE_EXPORT_NODEP 
insmod /lib/modules/2.5.52/noexport_doubledep-$BITNESS.ko 
INIT_MODULE: $SIZE_NOEXPORT_DOUBLEDEP " ]

done
