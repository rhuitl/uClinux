#! /bin/sh

MODTEST_DO_CREATE_MODULE=1
export MODTEST_DO_CREATE_MODULE

# Should fail to run (sys_create_module succeeds), not find insmod.old.
[ "`./insmod 2>&1`" = "Kernel requires old insmod, but couldn't run ./insmod.old: No such file or directory" ]

# Create one for it to find, put it in the path
echo '#! /bin/sh' > tests/tmp/insmod.old
echo 'echo -n INSMOD.OLD' >> tests/tmp/insmod.old
echo "for f; do echo -n \ \'\$f\'; done" >> tests/tmp/insmod.old
chmod a+x tests/tmp/insmod.old
PATH=`pwd`/tests/tmp:$PATH

# If explicit path given, shouldn't search path.
[ "`./insmod 2>&1`" = "Kernel requires old insmod, but couldn't run ./insmod.old: No such file or directory" ]

# No args expected
[ "`insmod`" = "INSMOD.OLD" ]

# Args intact
[ "`insmod --some-wierd-option foo`" = "INSMOD.OLD '--some-wierd-option' 'foo'" ]

