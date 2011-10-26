#! /bin/sh

MODTEST_DO_CREATE_MODULE=1
export MODTEST_DO_CREATE_MODULE

# Should fail to run (sys_create_module succeeds), not find modinfo.old.
[ "`./modinfo 2>&1`" = "Kernel requires old modinfo, but couldn't run ./modinfo.old: No such file or directory" ]

# Create one for it to find, put it in the path
echo '#! /bin/sh' > tests/tmp/modinfo.old
echo 'echo -n MODINFO.OLD' >> tests/tmp/modinfo.old
echo "for f; do echo -n \ \'\$f\'; done" >> tests/tmp/modinfo.old
chmod a+x tests/tmp/modinfo.old
PATH=`pwd`/tests/tmp:$PATH

# If explicit path given, shouldn't search path.
[ "`./modinfo 2>&1`" = "Kernel requires old modinfo, but couldn't run ./modinfo.old: No such file or directory" ]

# No args expected
[ "`modinfo 2>&1`" = "MODINFO.OLD" ]

# Args intact
[ "`modinfo --some-wierd-option foo 2>&1`" = "MODINFO.OLD '--some-wierd-option' 'foo'" ]
