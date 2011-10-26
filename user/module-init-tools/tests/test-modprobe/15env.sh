#! /bin/sh

for BITNESS in 32 64; do

MODTEST_OVERRIDE1=/lib/modules/2.5.52
MODTEST_OVERRIDE_WITH1=tests/data/$BITNESS/normal
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

MODTEST_OVERRIDE2=/lib/modules/2.5.52/noexport_nodep-$BITNESS.ko
MODTEST_OVERRIDE_WITH2=tests/data/$BITNESS/normal/noexport_nodep-$BITNESS.ko
export MODTEST_OVERRIDE2 MODTEST_OVERRIDE_WITH2

MODTEST_OVERRIDE3=/lib/modules/2.5.52/modules.dep
MODTEST_OVERRIDE_WITH3=tests/tmp/modules.dep
export MODTEST_OVERRIDE3 MODTEST_OVERRIDE_WITH3

MODTEST_OVERRIDE4=/etc/modprobe.conf
MODTEST_OVERRIDE_WITH4=tests/tmp/modprobe.conf
export MODTEST_OVERRIDE4 MODTEST_OVERRIDE_WITH4

MODTEST_OVERRIDE5=/proc/modules
MODTEST_OVERRIDE_WITH5=tests/tmp/proc
export MODTEST_OVERRIDE5 MODTEST_OVERRIDE_WITH5

MODTEST_OVERRIDE6=/etc/modprobe2.conf
MODTEST_OVERRIDE_WITH6=tests/tmp/modprobe2.conf
export MODTEST_OVERRIDE6 MODTEST_OVERRIDE_WITH6

# Now create modules.dep and modules.conf
echo /lib/modules/2.5.52/noexport_nodep-$BITNESS.ko: > tests/tmp/modules.dep
echo install foo modprobe noexport_nodep-$BITNESS > tests/tmp/modprobe.conf
echo install foo modprobe bar > tests/tmp/modprobe2.conf
echo install bar echo DOING BAR >> tests/tmp/modprobe2.conf

SIZE_NOEXPORT_NODEP=$(echo `wc -c < tests/data/$BITNESS/normal/noexport_nodep-$BITNESS.ko`)

# Test normal args, then in env.
[ "`./modprobe -v noexport_nodep-$BITNESS 2>&1`" = "insmod /lib/modules/2.5.52/noexport_nodep-$BITNESS.ko 
INIT_MODULE: $SIZE_NOEXPORT_NODEP " ]
[ "`MODPROBE_OPTIONS=-v ./modprobe noexport_nodep-$BITNESS 2>&1`" = "insmod /lib/modules/2.5.52/noexport_nodep-$BITNESS.ko 
INIT_MODULE: $SIZE_NOEXPORT_NODEP " ]

[ "`./modprobe -q noexport_nodep-$BITNESS 2>&1`" = "INIT_MODULE: $SIZE_NOEXPORT_NODEP " ]
[ "`MODPROBE_OPTIONS=-q ./modprobe noexport_nodep-$BITNESS 2>&1`" = "INIT_MODULE: $SIZE_NOEXPORT_NODEP " ]

[ "`./modprobe -n noexport_nodep-$BITNESS 2>&1`" = "" ]
[ "`MODPROBE_OPTIONS=-n ./modprobe noexport_nodep-$BITNESS 2>&1`" = "" ]

[ "`./modprobe -n -v noexport_nodep-$BITNESS 2>&1`" = "insmod /lib/modules/2.5.52/noexport_nodep-$BITNESS.ko " ]
[ "`MODPROBE_OPTIONS="-n -v" ./modprobe noexport_nodep-$BITNESS 2>&1`" = "insmod /lib/modules/2.5.52/noexport_nodep-$BITNESS.ko " ]

# Test argument inheritence.
MODTEST_DO_SYSTEM=1
export MODTEST_DO_SYSTEM

[ "`./modprobe -v foo 2>&1`" = "install modprobe noexport_nodep-$BITNESS
insmod /lib/modules/2.5.52/noexport_nodep-$BITNESS.ko 
INIT_MODULE: $SIZE_NOEXPORT_NODEP " ]
[ "`MODPROBE_OPTIONS=-v ./modprobe foo 2>&1`" = "install modprobe noexport_nodep-$BITNESS
insmod /lib/modules/2.5.52/noexport_nodep-$BITNESS.ko 
INIT_MODULE: $SIZE_NOEXPORT_NODEP " ]

[ "`./modprobe -C /etc/modprobe2.conf foo 2>&1`" = "DOING BAR" ]
[ "`MODPROBE_OPTIONS='-C /etc/modprobe2.conf' ./modprobe foo 2>&1`" = "DOING BAR" ]

[ "`./modprobe -C /etc/modprobe2.conf -v foo 2>&1`" = "install modprobe bar
install echo DOING BAR
DOING BAR" ]
[ "`MODPROBE_OPTIONS='-C /etc/modprobe2.conf' ./modprobe -v foo 2>&1`" = "install modprobe bar
install echo DOING BAR
DOING BAR" ]
done
