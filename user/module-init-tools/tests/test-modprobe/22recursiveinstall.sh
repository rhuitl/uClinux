#! /bin/sh

for BITNESS in 32 64; do

# Inputs
MODTEST_OVERRIDE1=/lib/modules/$MODTEST_UNAME
MODTEST_OVERRIDE_WITH1=tests/data/$BITNESS/normal
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

MODTEST_OVERRIDE2=/lib/modules/$MODTEST_UNAME/export_nodep-$BITNESS.ko
MODTEST_OVERRIDE_WITH2=tests/data/$BITNESS/normal/export_nodep-$BITNESS.ko
export MODTEST_OVERRIDE2 MODTEST_OVERRIDE_WITH2

MODTEST_OVERRIDE3=/lib/modules/$MODTEST_UNAME/noexport_dep-$BITNESS.ko
MODTEST_OVERRIDE_WITH3=tests/data/$BITNESS/normal/noexport_dep-$BITNESS.ko
export MODTEST_OVERRIDE3 MODTEST_OVERRIDE_WITH3

MODTEST_OVERRIDE4=/lib/modules/$MODTEST_UNAME/modules.dep
MODTEST_OVERRIDE_WITH4=tests/tmp/modules.dep
export MODTEST_OVERRIDE4 MODTEST_OVERRIDE_WITH4

MODTEST_OVERRIDE5=/etc/modprobe.conf
MODTEST_OVERRIDE_WITH5=tests/tmp/modprobe.conf
export MODTEST_OVERRIDE5 MODTEST_OVERRIDE_WITH5

MODTEST_OVERRIDE6=/lib/modules/$MODTEST_UNAME/modules.dep
MODTEST_OVERRIDE_WITH6=tests/tmp/modules.dep
export MODTEST_OVERRIDE6 MODTEST_OVERRIDE_WITH6

MODTEST_OVERRIDE7=/proc/modules
MODTEST_OVERRIDE_WITH7=tests/tmp/proc
export MODTEST_OVERRIDE7 MODTEST_OVERRIDE_WITH7

# Now create modules.dep
cat > tests/tmp/modules.dep <<EOF
/lib/modules/2.5.52/noexport_dep-$BITNESS.ko: /lib/modules/2.5.52/export_nodep-$BITNESS.ko
/lib/modules/2.5.52/export_nodep-$BITNESS.ko:
EOF

# Insertion
SIZE_EXPORT_NODEP=$(echo `wc -c < tests/data/$BITNESS/normal/export_nodep-$BITNESS.ko`)
SIZE_NOEXPORT_DEP=$(echo `wc -c < tests/data/$BITNESS/normal/noexport_dep-$BITNESS.ko`)

# Empty proc
touch tests/tmp/proc

# Check it pulls in both.
[ "`modprobe noexport_dep-$BITNESS 2>&1`" = "INIT_MODULE: $SIZE_EXPORT_NODEP 
INIT_MODULE: $SIZE_NOEXPORT_DEP " ]

# Check it's happy if we tell it dep is already instealled
cat > tests/tmp/proc <<EOF
export_nodep_$BITNESS 100 0 -
EOF
[ "`modprobe noexport_dep-$BITNESS 2>&1`" = "INIT_MODULE: $SIZE_NOEXPORT_DEP " ]

# If there's an install command, it will be done.
cat > tests/tmp/proc <<EOF
EOF

echo "install export_nodep-$BITNESS COMMAND" > tests/tmp/modprobe.conf
[ "`modprobe noexport_dep-$BITNESS 2>&1`" = "SYSTEM: COMMAND
INIT_MODULE: $SIZE_NOEXPORT_DEP " ]

# If it's in proc, install command WONT be done.
cat > tests/tmp/proc <<EOF
export_nodep_$BITNESS 100 0 -
EOF
[ "`modprobe noexport_dep-$BITNESS 2>&1`" = "INIT_MODULE: $SIZE_NOEXPORT_DEP " ]

# Do dependencies even if install command.
echo "install noexport_dep-$BITNESS COMMAND" > tests/tmp/modprobe.conf
cat > tests/tmp/proc <<EOF
EOF
[ "`modprobe noexport_dep-$BITNESS 2>&1`" = "INIT_MODULE: $SIZE_EXPORT_NODEP 
SYSTEM: COMMAND" ]

# Recursive install commands, WITH -q.
echo "install export_nodep-$BITNESS modprobe --first-time --ignore-install export_nodep-$BITNESS && { modprobe noexport_dep-$BITNESS; /bin/true; }" > tests/tmp/modprobe.conf

cat > tests/tmp/proc <<EOF
EOF

MODTEST_DO_SYSTEM=1
MODTEST_INSERT_PROC=1
export MODTEST_DO_SYSTEM MODTEST_INSERT_PROC
[ "`modprobe -qv -- export_nodep-$BITNESS`" = "install modprobe --first-time --ignore-install export_nodep-$BITNESS && { modprobe noexport_dep-$BITNESS; /bin/true; }
insmod /lib/modules/2.5.52/export_nodep-$BITNESS.ko 
insmod /lib/modules/2.5.52/noexport_dep-$BITNESS.ko " ]
unset MODTEST_DO_SYSTEM MODTEST_INSERT_PROC

done
