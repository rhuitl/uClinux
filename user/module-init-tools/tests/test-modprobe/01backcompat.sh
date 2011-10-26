#! /bin/sh

MODTEST_DO_CREATE_MODULE=1
export MODTEST_DO_CREATE_MODULE

# Should fail to run (sys_create_module succeeds), not find modprobe.old.
[ "`./modprobe 2>&1`" = "Kernel requires old modprobe, but couldn't run ./modprobe.old: No such file or directory" ]

# Create one for it to find, put it in the path
echo '#! /bin/sh' > tests/tmp/modprobe.old
echo 'echo -n MODPROBE.OLD' >> tests/tmp/modprobe.old
echo "for f; do echo -n \ \'\$f\'; done" >> tests/tmp/modprobe.old
chmod a+x tests/tmp/modprobe.old
PATH=`pwd`/tests/tmp:$PATH

# If explicit path given, shouldn't search path.
[ "`./modprobe 2>&1`" = "Kernel requires old modprobe, but couldn't run ./modprobe.old: No such file or directory" ]

# No args expected
[ "`modprobe`" = "MODPROBE.OLD" ]

# Args intact
[ "`modprobe --some-wierd-option foo`" = "MODPROBE.OLD '--some-wierd-option' 'foo'" ]
