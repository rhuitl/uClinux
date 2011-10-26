#! /bin/sh

for BITNESS in 32 64; do

# Create a simple config file.
cat > tests/tmp/modprobe.conf <<EOF
EOF

# Inputs
MODTEST_OVERRIDE1=/lib/modules/$MODTEST_UNAME
MODTEST_OVERRIDE_WITH1=tests/data/$BITNESS/normal
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

MODTEST_OVERRIDE2=/lib/modules/$MODTEST_UNAME/export_nodep-$BITNESS.ko
MODTEST_OVERRIDE_WITH2=tests/data/$BITNESS/normal/export_nodep-$BITNESS.ko
export MODTEST_OVERRIDE2 MODTEST_OVERRIDE_WITH2

MODTEST_OVERRIDE3=/lib/modules/$MODTEST_UNAME/modules.dep
MODTEST_OVERRIDE_WITH3=tests/tmp/modules.dep
export MODTEST_OVERRIDE3 MODTEST_OVERRIDE_WITH3

MODTEST_OVERRIDE4=/proc/modules
MODTEST_OVERRIDE_WITH4=FILE-WHICH-DOESNT-EXIST
export MODTEST_OVERRIDE4 MODTEST_OVERRIDE_WITH4

MODTEST_OVERRIDE5=/etc/modprobe.conf
MODTEST_OVERRIDE_WITH5=tests/tmp/modprobe.conf
export MODTEST_OVERRIDE5 MODTEST_OVERRIDE_WITH5

# Now create modules.dep
cat > tests/tmp/modules.dep <<EOF
/lib/modules/2.5.52/export_nodep-$BITNESS.ko:
tests/tmp/noexport_nodep-$BITNESS.ko:
EOF

MODPROBE_WAIT=tests/tmp/continue
export MODPROBE_WAIT

SIZE=$(echo `wc -c < tests/data/$BITNESS/normal/export_nodep-$BITNESS.ko`)

# Should be looping.
modprobe export_nodep-$BITNESS > tests/tmp/out1 2>&1 &
sleep 2

[ "`cat tests/tmp/out1`" = "Looping on tests/tmp/continue" ]

# Second one should wait.
modprobe -r export_nodep-$BITNESS > tests/tmp/out2 2>&1 &
sleep 2

[ "`cat tests/tmp/out2`" = "" ]

# Release first one
touch tests/tmp/continue
sleep 2

# Should have exited and cleaned up
[ "`cat tests/tmp/out1`" = "Looping on tests/tmp/continue
Removing tests/tmp/continue
INIT_MODULE: $SIZE " ]
[ ! -f tests/tmp/continue ]

# Second one should now be looping.
[ "`cat tests/tmp/out2`" = "Looping on tests/tmp/continue" ]

# Release second one
touch tests/tmp/continue
sleep 2

# Should have exited and cleaned up
[ "`cat tests/tmp/out2`" = "Looping on tests/tmp/continue
Removing tests/tmp/continue
DELETE_MODULE: export_nodep_$BITNESS EXCL " ]
[ ! -f tests/tmp/continue ]

# Lock gets dropped for install commands
cat > tests/tmp/modprobe.conf <<EOF
# Aliases to cause one command to hang.
install export_nodep-$BITNESS modprobe --ignore-install export_nodep-$BITNESS foo
remove export_nodep-$BITNESS modprobe -r --ignore-remove export_nodep-$BITNESS
EOF

MODTEST_DO_SYSTEM=1
export MODTEST_DO_SYSTEM

touch tests/tmp/continue
[ "`modprobe export_nodep-$BITNESS`" = "Looping on tests/tmp/continue
Removing tests/tmp/continue
INIT_MODULE: $SIZE foo" ]

touch tests/tmp/continue
[ "`modprobe -r export_nodep-$BITNESS`" = "Looping on tests/tmp/continue
Removing tests/tmp/continue
DELETE_MODULE: export_nodep_$BITNESS EXCL " ]

# Check that a read-only module still loads.
cp tests/data/$BITNESS/normal/noexport_nodep-$BITNESS.ko tests/tmp/
chmod a-w tests/tmp/noexport_nodep-$BITNESS.ko
unset MODPROBE_WAIT

SIZE2=$(echo `wc -c < tests/tmp/noexport_nodep-$BITNESS.ko`)

[ "`modprobe noexport_nodep-$BITNESS`" = "INIT_MODULE: $SIZE2 " ]
done
