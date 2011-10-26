#! /bin/sh

MODTEST_DO_CREATE_MODULE=1
export MODTEST_DO_CREATE_MODULE

# Should fail to run (sys_create_module succeeds), not find rmmod.old.
[ "`./rmmod 2>&1`" = "Kernel requires old rmmod, but couldn't run ./rmmod.old: No such file or directory" ]

# Create one for it to find, put it in the path
echo '#! /bin/sh' > tests/tmp/rmmod.old
echo 'echo -n RMMOD.OLD' >> tests/tmp/rmmod.old
echo "for f; do echo -n \ \'\$f\'; done" >> tests/tmp/rmmod.old
chmod a+x tests/tmp/rmmod.old
PATH=`pwd`/tests/tmp:$PATH

# If explicit path given, shouldn't search path.
[ "`./rmmod 2>&1`" = "Kernel requires old rmmod, but couldn't run ./rmmod.old: No such file or directory" ]

# No args expected
[ "`rmmod 2>&1`" = "RMMOD.OLD" ]

# Args intact
[ "`rmmod --some-wierd-option foo 2>&1`" = "RMMOD.OLD '--some-wierd-option' 'foo'" ]

