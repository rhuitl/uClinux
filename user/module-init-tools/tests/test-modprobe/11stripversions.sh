#! /bin/sh
# Test the version removal code

section_attributes()
{
    readelf -W -S "$1" | cut -d\] -f2- | awk '{print $1 " " $7}' | grep -w -- "$2"
}

for BITNESS in 32 64; do

# We need to dump the module to make sure the name has changed.
MODTEST_DUMP_INIT=1
export MODTEST_DUMP_INIT

MODTEST_OVERRIDE1=/lib/modules/$MODTEST_UNAME/modules.dep
MODTEST_OVERRIDE_WITH1=tests/tmp/modules.dep
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

MODTEST_OVERRIDE2=/lib/modules/$MODTEST_UNAME/rename-version-$BITNESS.ko
MODTEST_OVERRIDE_WITH2=tests/data/$BITNESS/rename/rename-version-$BITNESS.ko
export MODTEST_OVERRIDE2 MODTEST_OVERRIDE_WITH2

MODTEST_OVERRIDE3=/etc/modprobe.conf
MODTEST_OVERRIDE_WITH3=tests/tmp/DOES_NOT_EXIST
export MODTEST_OVERRIDE3 MODTEST_OVERRIDE_WITH3

# Set up modules.dep file (neither has dependencies).
echo "# A comment" > tests/tmp/modules.dep
echo "/lib/modules/$MODTEST_UNAME/rename-version-$BITNESS.ko:" >> tests/tmp/modules.dep

# Check it without removing.
[ "`modprobe rename-version-$BITNESS 2> tests/tmp/out`" = "" ]
[ "`section_attributes tests/tmp/out __versions`" = "__versions A" ]
[ "`section_attributes tests/tmp/out __vermagic`" = "__vermagic A" ]

# Now remove them (turns off ALLOC bit)
[ "`modprobe --force rename-version-$BITNESS 2> tests/tmp/out`" = "" ]
[ "`section_attributes tests/tmp/out __versions`" = "__versions 0" ]
[ "`section_attributes tests/tmp/out __vermagic`" = "__vermagic 0" ]

# Now remove them individually instead.
[ "`modprobe --force-vermagic rename-version-$BITNESS 2> tests/tmp/out`" = "" ]
[ "`section_attributes tests/tmp/out __versions`" = "__versions A" ]
[ "`section_attributes tests/tmp/out __vermagic`" = "__vermagic 0" ]
[ "`modprobe --force-modversion rename-version-$BITNESS 2> tests/tmp/out`" = "" ]
[ "`section_attributes tests/tmp/out __versions`" = "__versions 0" ]
[ "`section_attributes tests/tmp/out __vermagic`" = "__vermagic A" ]

done

exit 0
