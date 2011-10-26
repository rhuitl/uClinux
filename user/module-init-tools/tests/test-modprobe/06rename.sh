#! /bin/sh
# Test the module renaming code.

for BITNESS in 32 64; do

# We need to dump the module to make sure the name has changed.
MODTEST_DUMP_INIT=1
export MODTEST_DUMP_INIT

MODTEST_OVERRIDE1=/lib/modules/$MODTEST_UNAME/modules.dep
MODTEST_OVERRIDE_WITH1=tests/tmp/modules.dep
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

MODTEST_OVERRIDE2=/lib/modules/$MODTEST_UNAME/rename-new-$BITNESS.ko
MODTEST_OVERRIDE_WITH2=tests/data/$BITNESS/rename/rename-new-$BITNESS.ko
export MODTEST_OVERRIDE2 MODTEST_OVERRIDE_WITH2

MODTEST_OVERRIDE3=/lib/modules/$MODTEST_UNAME/rename-old-$BITNESS.ko
MODTEST_OVERRIDE_WITH3=tests/data/$BITNESS/rename/rename-old-$BITNESS.ko
export MODTEST_OVERRIDE3 MODTEST_OVERRIDE_WITH3

MODTEST_OVERRIDE4=/etc/modprobe.conf
MODTEST_OVERRIDE_WITH4=tests/tmp/DOES_NOT_EXIST
export MODTEST_OVERRIDE4 MODTEST_OVERRIDE_WITH4

MODTEST_OVERRIDE5=/proc/modules
MODTEST_OVERRIDE_WITH5=tests/tmp/modules
export MODTEST_OVERRIDE5 MODTEST_OVERRIDE_WITH5

# Set up modules.dep file (neither has dependencies).
echo "# A comment" > tests/tmp/modules.dep
echo "/lib/modules/$MODTEST_UNAME/rename-new-$BITNESS.ko:" >> tests/tmp/modules.dep
echo "/lib/modules/$MODTEST_UNAME/rename-old-$BITNESS.ko:" >> tests/tmp/modules.dep

# Test old-style module 
[ "`modprobe rename-old-$BITNESS 2> tests/tmp/out`" = "" ]
strings tests/tmp/out | grep -q 'rename_old'
if strings tests/tmp/out | grep -q 'short'; then exit 1; fi

[ "`modprobe -o short rename-old-$BITNESS 2> tests/tmp/out`" = "" ]
if strings tests/tmp/out | grep -q 'rename_old'; then exit 1; fi
strings tests/tmp/out | grep -q 'short'

[ "`modprobe -o very_very_long_name rename-old-$BITNESS 2> tests/tmp/out`" = "" ]
if strings tests/tmp/out | grep -q 'rename_old'; then exit 1; fi
strings tests/tmp/out | grep -q 'very_very_long_name'

[ "`modprobe -o short rename-old-$BITNESS 2> tests/tmp/out`" = "" ]
if strings tests/tmp/out | grep -q 'rename_old'; then exit 1; fi
strings tests/tmp/out | grep -q 'short'

[ "`modprobe -o very_very_long_name rename-old-$BITNESS 2> tests/tmp/out`" = "" ]
if strings tests/tmp/out | grep -q 'rename_old'; then exit 1; fi
strings tests/tmp/out | grep -q 'very_very_long_name'

[ "`modprobe --name short rename-old-$BITNESS 2> tests/tmp/out`" = "" ]
if strings tests/tmp/out | grep -q 'rename_old'; then exit 1; fi
strings tests/tmp/out | grep -q 'short'

[ "`modprobe --name very_very_long_name rename-old-$BITNESS 2> tests/tmp/out`" = "" ]
if strings tests/tmp/out | grep -q 'rename_old'; then exit 1; fi
strings tests/tmp/out | grep -q 'very_very_long_name'

[ "`modprobe --name=short rename-old-$BITNESS 2> tests/tmp/out`" = "" ]
if strings tests/tmp/out | grep -q 'rename_old'; then exit 1; fi
strings tests/tmp/out | grep -q 'short'

[ "`modprobe --name=very_very_long_name rename-old-$BITNESS 2> tests/tmp/out`" = "" ]
if strings tests/tmp/out | grep -q 'rename_old'; then exit 1; fi
strings tests/tmp/out | grep -q 'very_very_long_name'

# Test new-style module 
[ "`modprobe rename-new-$BITNESS 2> tests/tmp/out`" = "" ]
strings tests/tmp/out | grep -q 'rename_new'
if strings tests/tmp/out | grep -q 'short'; then exit 1; fi

[ "`modprobe -o short rename-new-$BITNESS 2> tests/tmp/out`" = "" ]
if strings tests/tmp/out | grep -q 'rename_new'; then exit 1; fi
strings tests/tmp/out | grep -q 'short'

[ "`modprobe -o very_very_long_name rename-new-$BITNESS 2> tests/tmp/out`" = "" ]
if strings tests/tmp/out | grep -q 'rename_new'; then exit 1; fi
strings tests/tmp/out | grep -q 'very_very_long_name'

[ "`modprobe -o short rename-new-$BITNESS 2> tests/tmp/out`" = "" ]
if strings tests/tmp/out | grep -q 'rename_new'; then exit 1; fi
strings tests/tmp/out | grep -q 'short'

[ "`modprobe -o very_very_long_name rename-new-$BITNESS 2> tests/tmp/out`" = "" ]
if strings tests/tmp/out | grep -q 'rename_new'; then exit 1; fi
strings tests/tmp/out | grep -q 'very_very_long_name'

[ "`modprobe --name short rename-new-$BITNESS 2> tests/tmp/out`" = "" ]
if strings tests/tmp/out | grep -q 'rename_new'; then exit 1; fi
strings tests/tmp/out | grep -q 'short'

[ "`modprobe --name very_very_long_name rename-new-$BITNESS 2> tests/tmp/out`" = "" ]
if strings tests/tmp/out | grep -q 'rename_new'; then exit 1; fi
strings tests/tmp/out | grep -q 'very_very_long_name'

[ "`modprobe --name=short rename-new-$BITNESS 2> tests/tmp/out`" = "" ]
if strings tests/tmp/out | grep -q 'rename_new'; then exit 1; fi
strings tests/tmp/out | grep -q 'short'

[ "`modprobe --name=very_very_long_name rename-new-$BITNESS 2> tests/tmp/out`" = "" ]
if strings tests/tmp/out | grep -q 'rename_new'; then exit 1; fi
strings tests/tmp/out | grep -q 'very_very_long_name'

cat > tests/tmp/proc <<EOF
newname 100 0 -
EOF
[ "`modprobe --name=newname -r rename-new-$BITNESS 2>&1`" = "DELETE_MODULE: newname EXCL " ]
done
