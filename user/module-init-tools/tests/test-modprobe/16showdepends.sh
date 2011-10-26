#! /bin/sh
# Test --show-depends.

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

# Empty proc
cp /dev/null tests/tmp/proc

[ "`modprobe --show-depends noexport_nodep-$BITNESS 2>>tests/tmp/stderr`" = "insmod /lib/modules/2.5.52/noexport_nodep-$BITNESS.ko " ]
[ "`modprobe --show-depends export_nodep-$BITNESS 2>>tests/tmp/stderr`" = "insmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko " ]
[ "`modprobe --show-depends noexport_dep-$BITNESS 2>>tests/tmp/stderr`" = "insmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko 
insmod /lib/modules/2.5.52/noexport_dep-$BITNESS.ko " ]
[ "`modprobe --show-depends export_dep-$BITNESS 2>>tests/tmp/stderr`" = "insmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko 
insmod /lib/modules/2.5.52/export_dep-$BITNESS.ko " ]
[ "`modprobe --show-depends noexport_doubledep-$BITNESS 2>>tests/tmp/stderr`" = "insmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko 
insmod /lib/modules/2.5.52/export_dep-$BITNESS.ko 
insmod /lib/modules/2.5.52/noexport_doubledep-$BITNESS.ko " ]

# Nothing in stderr...
[ `wc -c < tests/tmp/stderr` = 0 ]

# All in proc; should make no difference.
cat > tests/tmp/proc <<EOF
noexport_nodep_$BITNESS 100 0 -
export_nodep_$BITNESS 100 0 -
noexport_dep_$BITNESS 100 0 export_nodep_$BITNESS,
export_dep_$BITNESS 100 0 export_nodep_$BITNESS,
noexport_doubledep_$BITNESS 100 0 export_dep_$BITNESS,export_nodep_$BITNESS
EOF

[ "`modprobe --show-depends noexport_nodep-$BITNESS 2>>tests/tmp/stderr`" = "insmod /lib/modules/2.5.52/noexport_nodep-$BITNESS.ko " ]
[ "`modprobe --show-depends export_nodep-$BITNESS 2>>tests/tmp/stderr`" = "insmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko " ]
[ "`modprobe --show-depends noexport_dep-$BITNESS 2>>tests/tmp/stderr`" = "insmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko 
insmod /lib/modules/2.5.52/noexport_dep-$BITNESS.ko " ]
[ "`modprobe --show-depends export_dep-$BITNESS 2>>tests/tmp/stderr`" = "insmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko 
insmod /lib/modules/2.5.52/export_dep-$BITNESS.ko " ]
[ "`modprobe --show-depends noexport_doubledep-$BITNESS 2>>tests/tmp/stderr`" = "insmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko 
insmod /lib/modules/2.5.52/export_dep-$BITNESS.ko 
insmod /lib/modules/2.5.52/noexport_doubledep-$BITNESS.ko " ]

# Nothing in stderr...
[ `wc -c < tests/tmp/stderr` = 0 ]

# Module commands printed, ignored.
cat > tests/tmp/modprobe.conf <<EOF
install noexport_nodep-$BITNESS echo noexport_nodep-$BITNESS
install export_nodep-$BITNESS echo export_nodep-$BITNESS
install noexport_dep-$BITNESS echo noexport_dep-$BITNESS
install export_dep-$BITNESS echo export_dep-$BITNESS
install noexport_doubledep-$BITNESS echo noexport_doubledep-$BITNESS
EOF

[ "`modprobe --show-depends noexport_nodep-$BITNESS 2>>tests/tmp/stderr`" = "install echo noexport_nodep-$BITNESS" ]
[ "`modprobe --show-depends export_nodep-$BITNESS 2>>tests/tmp/stderr`" = "install echo export_nodep-$BITNESS" ]
[ "`modprobe --show-depends noexport_dep-$BITNESS 2>>tests/tmp/stderr`" = "install echo export_nodep-$BITNESS
install echo noexport_dep-$BITNESS" ]
[ "`modprobe --show-depends export_dep-$BITNESS 2>>tests/tmp/stderr`" = "install echo export_nodep-$BITNESS
install echo export_dep-$BITNESS" ]
[ "`modprobe --show-depends noexport_doubledep-$BITNESS 2>>tests/tmp/stderr`" = "install echo export_nodep-$BITNESS
install echo export_dep-$BITNESS
install echo noexport_doubledep-$BITNESS" ]
# Nothing in stderr...
[ `wc -c < tests/tmp/stderr` = 0 ]

# Module options printed.
cat > tests/tmp/modprobe.conf <<EOF
options noexport_nodep-$BITNESS opt1
options export_nodep-$BITNESS opt2
options noexport_dep-$BITNESS opt3
options export_dep-$BITNESS opt4
options noexport_doubledep-$BITNESS opt5
EOF

[ "`modprobe --show-depends noexport_nodep-$BITNESS 2>>tests/tmp/stderr`" = "insmod /lib/modules/2.5.52/noexport_nodep-$BITNESS.ko opt1" ]
[ "`modprobe --show-depends export_nodep-$BITNESS 2>>tests/tmp/stderr`" = "insmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko opt2" ]
[ "`modprobe --show-depends noexport_dep-$BITNESS 2>>tests/tmp/stderr`" = "insmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko opt2
insmod /lib/modules/2.5.52/noexport_dep-$BITNESS.ko opt3" ]
[ "`modprobe --show-depends export_dep-$BITNESS 2>>tests/tmp/stderr`" = "insmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko opt2
insmod /lib/modules/2.5.52/export_dep-$BITNESS.ko opt4" ]
[ "`modprobe --show-depends noexport_doubledep-$BITNESS 2>>tests/tmp/stderr`" = "insmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko opt2
insmod /lib/modules/2.5.52/export_dep-$BITNESS.ko opt4
insmod /lib/modules/2.5.52/noexport_doubledep-$BITNESS.ko opt5" ]
# Nothing in stderr...
[ `wc -c < tests/tmp/stderr` = 0 ]

# Via aliases works.
cat > tests/tmp/modprobe.conf <<EOF
options noexport_nodep-$BITNESS opt1
alias foo noexport_nodep-$BITNESS
options foo fooopt
EOF

[ "`modprobe --show-depends foo`" = "insmod /lib/modules/2.5.52/noexport_nodep-$BITNESS.ko fooopt opt1" ]
# Nothing in stderr...
[ `wc -c < tests/tmp/stderr` = 0 ]

rm tests/tmp/modprobe.conf
done
