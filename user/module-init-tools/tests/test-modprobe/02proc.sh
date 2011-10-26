#! /bin/sh

# Test handling of /proc/modules.

for BITNESS in 32 64; do

# Inputs
MODTEST_OVERRIDE1=/lib/modules/$MODTEST_UNAME
MODTEST_OVERRIDE_WITH1=tests/data/$BITNESS/normal
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

MODTEST_OVERRIDE2=/lib/modules/$MODTEST_UNAME/noexport_nodep-$BITNESS.ko
MODTEST_OVERRIDE_WITH2=tests/data/$BITNESS/normal/noexport_nodep-$BITNESS.ko
export MODTEST_OVERRIDE2 MODTEST_OVERRIDE_WITH2

MODTEST_OVERRIDE3=/lib/modules/$MODTEST_UNAME/export_nodep-$BITNESS.ko
MODTEST_OVERRIDE_WITH3=tests/data/$BITNESS/normal/export_nodep-$BITNESS.ko
export MODTEST_OVERRIDE3 MODTEST_OVERRIDE_WITH3

MODTEST_OVERRIDE4=/lib/modules/$MODTEST_UNAME/modules.dep
MODTEST_OVERRIDE_WITH4=tests/tmp/modules.dep
export MODTEST_OVERRIDE4 MODTEST_OVERRIDE_WITH4

MODTEST_OVERRIDE5=/etc/modprobe.conf
MODTEST_OVERRIDE_WITH5=FILE-WHICH-DOESNT-EXIST
export MODTEST_OVERRIDE5 MODTEST_OVERRIDE_WITH5

MODTEST_OVERRIDE6=/lib/modules/$MODTEST_UNAME/modules.dep
MODTEST_OVERRIDE_WITH6=tests/tmp/modules.dep
export MODTEST_OVERRIDE6 MODTEST_OVERRIDE_WITH6

MODTEST_OVERRIDE7=/proc/modules
MODTEST_OVERRIDE_WITH7=tests/tmp/proc
export MODTEST_OVERRIDE7 MODTEST_OVERRIDE_WITH7

# Now create modules.dep
cat > tests/tmp/modules.dep <<EOF
/lib/modules/2.5.52/noexport_nodep-$BITNESS.ko:
/lib/modules/2.5.52/export_nodep-$BITNESS.ko:
EOF

SIZE_NOEXPORT_NODEP=$(echo `wc -c < tests/data/$BITNESS/normal/noexport_nodep-$BITNESS.ko`)
SIZE_EXPORT_NODEP=$(echo `wc -c < tests/data/$BITNESS/normal/export_nodep-$BITNESS.ko`)

# If it can't open /proc/modules, it should try anyway.
rm -f tests/tmp/proc

[ "`modprobe noexport_nodep-$BITNESS 2>&1`" = "INIT_MODULE: $SIZE_NOEXPORT_NODEP " ]
[ "`modprobe export_nodep-$BITNESS 2>&1`" = "INIT_MODULE: $SIZE_EXPORT_NODEP " ]

[ "`modprobe -r noexport_nodep-$BITNESS 2>&1`" = "DELETE_MODULE: noexport_nodep_$BITNESS EXCL " ]
[ "`modprobe -r export_nodep-$BITNESS 2>&1`" = "DELETE_MODULE: export_nodep_$BITNESS EXCL " ]

# If it doesn't exist in /proc/modules, remove should succeed.
touch tests/tmp/proc
[ "`modprobe noexport_nodep-$BITNESS 2>&1`" = "INIT_MODULE: $SIZE_NOEXPORT_NODEP " ]
[ "`modprobe export_nodep-$BITNESS 2>&1`" = "INIT_MODULE: $SIZE_EXPORT_NODEP " ]
[ "`modprobe -r -v noexport_nodep-$BITNESS 2>&1; echo $?`" = "0" ]
[ "`modprobe -r -v export_nodep-$BITNESS 2>&1; echo $?`" = "0" ]
[ "`modprobe -r -v noexport-nodep-$BITNESS 2>&1; echo $?`" = "0" ]
[ "`modprobe -r -v export-nodep-$BITNESS 2>&1; echo $?`" = "0" ]
# ... unless --first-time is specified (won't print status due to set -e).
[ "`modprobe --first-time -r noexport_nodep-$BITNESS 2>&1; echo $?`" = "FATAL: Module noexport_nodep_$BITNESS is not in kernel." ]
[ "`modprobe --first-time -r export_nodep-$BITNESS 2>&1; echo $?`" = "FATAL: Module export_nodep_$BITNESS is not in kernel." ]
[ "`modprobe --first-time -r noexport-nodep-$BITNESS 2>&1; echo $?`" = "FATAL: Module noexport_nodep_$BITNESS is not in kernel." ]
[ "`modprobe --first-time -r export-nodep-$BITNESS 2>&1; echo $?`" = "FATAL: Module export_nodep_$BITNESS is not in kernel." ]

# Old-style /proc (no unload support).
echo "noexport_nodep_$BITNESS $SIZE_NOEXPORT_NODEP" > tests/tmp/proc
echo "export_nodep_$BITNESS $SIZE_EXPORT_NODEP" >> tests/tmp/proc

# If it does exist, insertion should "succeed".
[ "`modprobe -v noexport_nodep-$BITNESS 2>&1; echo $?`" = "0" ]
[ "`modprobe -v export_nodep-$BITNESS 2>&1; echo $?`" = "0" ]
[ "`modprobe -v noexport-nodep-$BITNESS 2>&1; echo $?`" = "0" ]
[ "`modprobe -v export-nodep-$BITNESS 2>&1; echo $?`" = "0" ]
# .. unless --first-time is specified.
[ "`modprobe --first-time noexport_nodep-$BITNESS 2>&1; echo $?`" = "FATAL: Module noexport_nodep_$BITNESS already in kernel." ]
[ "`modprobe --first-time export_nodep-$BITNESS 2>&1; echo $?`" = "FATAL: Module export_nodep_$BITNESS already in kernel." ]
[ "`modprobe --first-time noexport-nodep-$BITNESS 2>&1; echo $?`" = "FATAL: Module noexport_nodep_$BITNESS already in kernel." ]
[ "`modprobe --first-time export-nodep-$BITNESS 2>&1; echo $?`" = "FATAL: Module export_nodep_$BITNESS already in kernel." ]

# Removal should still try.
[ "`modprobe -r noexport_nodep-$BITNESS 2>&1`" = "DELETE_MODULE: noexport_nodep_$BITNESS EXCL " ]
[ "`modprobe -r export_nodep-$BITNESS 2>&1`" = "DELETE_MODULE: export_nodep_$BITNESS EXCL " ]

# New-style /proc without unload support
echo "noexport_nodep_$BITNESS $SIZE_NOEXPORT_NODEP - -" > tests/tmp/proc
echo "export_nodep_$BITNESS $SIZE_EXPORT_NODEP - -" >> tests/tmp/proc

[ "`modprobe --first-time noexport_nodep-$BITNESS 2>&1`" = "FATAL: Module noexport_nodep_$BITNESS already in kernel." ]
[ "`modprobe --first-time export_nodep-$BITNESS 2>&1`" = "FATAL: Module export_nodep_$BITNESS already in kernel." ]
[ "`modprobe --first-time noexport-nodep-$BITNESS 2>&1`" = "FATAL: Module noexport_nodep_$BITNESS already in kernel." ]
[ "`modprobe --first-time export-nodep-$BITNESS 2>&1`" = "FATAL: Module export_nodep_$BITNESS already in kernel." ]
# Removal should still try.
[ "`modprobe -r noexport_nodep-$BITNESS 2>&1`" = "DELETE_MODULE: noexport_nodep_$BITNESS EXCL " ]
[ "`modprobe -r export_nodep-$BITNESS 2>&1`" = "DELETE_MODULE: export_nodep_$BITNESS EXCL " ]

# Should fail if refcounts non-zero.  Old-style
echo "noexport_nodep_$BITNESS $SIZE_NOEXPORT_NODEP 1" > tests/tmp/proc
echo "export_nodep_$BITNESS $SIZE_EXPORT_NODEP 1" >> tests/tmp/proc

[ "`modprobe -r noexport_nodep-$BITNESS 2>&1`" = "FATAL: Module noexport_nodep_$BITNESS is in use." ]
[ "`modprobe -r export_nodep-$BITNESS 2>&1`" = "FATAL: Module export_nodep_$BITNESS is in use." ]
[ "`modprobe -r noexport-nodep-$BITNESS 2>&1`" = "FATAL: Module noexport_nodep_$BITNESS is in use." ]
[ "`modprobe -r export-nodep-$BITNESS 2>&1`" = "FATAL: Module export_nodep_$BITNESS is in use." ]

# New-style /proc
echo "noexport_nodep_$BITNESS $SIZE_NOEXPORT_NODEP 1 -" > tests/tmp/proc
echo "export_nodep_$BITNESS $SIZE_EXPORT_NODEP 1 something_else, extrafield" >> tests/tmp/proc

[ "`modprobe --first-time noexport_nodep-$BITNESS 2>&1`" = "FATAL: Module noexport_nodep_$BITNESS already in kernel." ]
[ "`modprobe --first-time export_nodep-$BITNESS 2>&1`" = "FATAL: Module export_nodep_$BITNESS already in kernel." ]
[ "`modprobe --first-time noexport-nodep-$BITNESS 2>&1`" = "FATAL: Module noexport_nodep_$BITNESS already in kernel." ]
[ "`modprobe --first-time export-nodep-$BITNESS 2>&1`" = "FATAL: Module export_nodep_$BITNESS already in kernel." ]

[ "`modprobe -r noexport_nodep-$BITNESS 2>&1`" = "FATAL: Module noexport_nodep_$BITNESS is in use." ]
[ "`modprobe -r export_nodep-$BITNESS 2>&1`" = "FATAL: Module export_nodep_$BITNESS is in use." ]
[ "`modprobe -r noexport-nodep-$BITNESS 2>&1`" = "FATAL: Module noexport_nodep_$BITNESS is in use." ]
[ "`modprobe -r export-nodep-$BITNESS 2>&1`" = "FATAL: Module export_nodep_$BITNESS is in use." ]

done
