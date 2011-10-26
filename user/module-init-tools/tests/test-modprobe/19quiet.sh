#! /bin/sh

for BITNESS in 32 64; do

MODTEST_OVERRIDE1=/lib/modules/$MODTEST_UNAME/modules.dep
MODTEST_OVERRIDE_WITH1=tests/tmp/modules.dep
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

MODTEST_OVERRIDE2=/lib/modules/$MODTEST_UNAME/noexport_nodep-$BITNESS.ko
MODTEST_OVERRIDE_WITH2=tests/data/$BITNESS/normal/noexport_nodep-$BITNESS.ko
export MODTEST_OVERRIDE2 MODTEST_OVERRIDE_WITH2

MODTEST_OVERRIDE3=/etc/modprobe.conf
MODTEST_OVERRIDE_WITH3=tests/tmp/modprobe.conf
export MODTEST_OVERRIDE3 MODTEST_OVERRIDE_WITH3

MODTEST_OVERRIDE4=/proc/modules
MODTEST_OVERRIDE_WITH4=tests/tmp/proc
export MODTEST_OVERRIDE4 MODTEST_OVERRIDE_WITH4

# Set up modules.dep file.
echo "# A comment" > tests/tmp/modules.dep
echo "/lib/modules/$MODTEST_UNAME/noexport_nodep-$BITNESS.ko:" >> tests/tmp/modules.dep
echo "/lib/modules/$MODTEST_UNAME/bogus-$BITNESS.ko:" >> tests/tmp/modules.dep

echo "install some-command modprobe crap && echo SUCCESS" > tests/tmp/modprobe.conf 
echo "remove some-command modprobe -r crap && echo SUCCESS" >> tests/tmp/modprobe.conf 
echo "alias foobar crap" >> tests/tmp/modprobe.conf 

SIZE=$(echo `wc -c < tests/data/$BITNESS/normal/noexport_nodep-$BITNESS.ko`)

# -q works as normal.
[ "`modprobe -q noexport_nodep-$BITNESS 2>&1`" = "INIT_MODULE: $SIZE " ]

# -q on non-existent fail, quietly.
[ "`modprobe -q crap 2>&1`" = "" ]
if modprobe -q crap; then exit 1; fi

# -q on alias to non-existent succeeds, quietly.
[ "`modprobe -q foobar 2>&1`" = "" ]
if modprobe -q foobar; then exit 1; fi

# -q on some other problem gives errors.
[ "`modprobe -q bogus-$BITNESS 2>&1`" != "" ]
if modprobe -q bogus-$BITNESS 2>/dev/null; then exit 1; fi

MODTEST_DO_SYSTEM=1
export MODTEST_DO_SYSTEM
# Normal install command will fail.
[ "`modprobe some-command 2>&1`" = "FATAL: Module crap not found.
FATAL: Error running install command for some_command" ]
if modprobe some-command 2>/dev/null; then exit 1; fi

# -q doesn't cause "modprobe crap" to succeed, but is passed through install.
[ "`modprobe -q some-command 2>&1`" = "FATAL: Error running install command for some_command" ]
if modprobe -q some-command 2>/dev/null; then exit 1; fi

## Remove
# All in proc
cat > tests/tmp/proc <<EOF
noexport_nodep_$BITNESS 100 0 -
EOF

# -q works as normal.
[ "`modprobe -r -q noexport_nodep-$BITNESS 2>&1`" = "DELETE_MODULE: noexport_nodep_$BITNESS EXCL " ]

# -q on non-existent module fails, silently.
[ "`modprobe -r -q crap 2>&1`" = "" ]
if modprobe -r -q crap; then exit 1; fi

MODTEST_DO_SYSTEM=1
export MODTEST_DO_SYSTEM
# Normal remove command will fail.
[ "`modprobe -r some-command 2>&1`" = "FATAL: Module crap not found.
FATAL: Error running remove command for some_command" ]
if modprobe -r some-command 2>/dev/null; then exit 1; fi

# -q doesn't cause "modprobe -r crap" to succeed, but silences it.
[ "`modprobe -r -q some-command 2>&1`" = "FATAL: Error running remove command for some_command" ]
if modprobe -r -q some-command 2>/dev/null; then exit 1; fi

done
