#! /bin/sh

MODTEST_DO_CREATE_MODULE=1
export MODTEST_DO_CREATE_MODULE

# Should fail to run (sys_create_module succeeds), not find lsmod.old.
[ "`./lsmod 2>&1`" = "Kernel requires old lsmod, but couldn't run ./lsmod.old: No such file or directory" ]

# Create one for it to find, put it in the path
echo '#! /bin/sh' > tests/tmp/lsmod.old
echo 'echo -n LSMOD.OLD' >> tests/tmp/lsmod.old
echo "for f; do echo -n \ \'\$f\'; done" >> tests/tmp/lsmod.old
chmod a+x tests/tmp/lsmod.old
PATH=`pwd`/tests/tmp:$PATH

# If explicit path given, shouldn't search path.
[ "`./lsmod 2>&1`" = "Kernel requires old lsmod, but couldn't run ./lsmod.old: No such file or directory" ]

# No args expected
[ "`lsmod 2>&1`" = "LSMOD.OLD" ]

# Args intact
[ "`lsmod --some-wierd-option foo 2>&1`" = "LSMOD.OLD '--some-wierd-option' 'foo'" ]
