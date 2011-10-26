#! /bin/sh

for BITNESS in 32 64; do

# Inputs
MODTEST_OVERRIDE1=/lib/modules/2.5.53
MODTEST_OVERRIDE_WITH1=tests/data/$BITNESS/normal
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

MODTEST_OVERRIDE2=/lib/modules/2.5.53/noexport_nodep-$BITNESS.ko
MODTEST_OVERRIDE_WITH2=tests/data/$BITNESS/normal/noexport_nodep-$BITNESS.ko
export MODTEST_OVERRIDE2 MODTEST_OVERRIDE_WITH2

MODTEST_OVERRIDE3=/lib/modules/2.5.53/modules.dep
MODTEST_OVERRIDE_WITH3=tests/tmp/modules.dep
export MODTEST_OVERRIDE3 MODTEST_OVERRIDE_WITH3

MODTEST_OVERRIDE4=/etc/modprobe.conf
MODTEST_OVERRIDE_WITH4=tests/tmp/modprobe.conf
export MODTEST_OVERRIDE4 MODTEST_OVERRIDE_WITH4

MODTEST_OVERRIDE5=/proc/modules
MODTEST_OVERRIDE_WITH5=tests/tmp/proc
export MODTEST_OVERRIDE5 MODTEST_OVERRIDE_WITH5

# Now create modules.dep
cat > tests/tmp/modules.dep <<EOF
# Should handle comments.
/lib/modules/2.5.53/noexport_nodep-$BITNESS.ko:
EOF

MODTEST_DO_CREATE_MODULE=1
export MODTEST_DO_CREATE_MODULE

# Insertion
SIZE_NOEXPORT_NODEP=$(echo `wc -c < tests/data/$BITNESS/normal/noexport_nodep-$BITNESS.ko`)

# Normally would do back compat, but --set-version will suppress it.
[ "`./modprobe noexport_nodep-$BITNESS 2>&1`" = "Kernel requires old modprobe, but couldn't run ./modprobe.old: No such file or directory" ]
[ "`./modprobe --set-version=2.5.53 noexport_nodep-$BITNESS 2>&1`" = "INIT_MODULE: $SIZE_NOEXPORT_NODEP " ]

done
