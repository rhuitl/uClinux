#! /bin/sh

# Backwards compat using explicit version number
[ "`./depmod 1.5.48 2>&1`" = "Version requires old depmod, but couldn't run ./depmod.old: No such file or directory" ]
[ "`./depmod 2.0.1 2>&1`" = "Version requires old depmod, but couldn't run ./depmod.old: No such file or directory" ]
[ "`./depmod 2.4.20 2>&1`" = "Version requires old depmod, but couldn't run ./depmod.old: No such file or directory" ]
[ "`./depmod 2.4.49 2>&1`" = "Version requires old depmod, but couldn't run ./depmod.old: No such file or directory" ]

# Implicit version number.
[ "`MODTEST_UNAME=1.5.48 ./depmod 2>&1`" = "Version requires old depmod, but couldn't run ./depmod.old: No such file or directory" ]
[ "`MODTEST_UNAME=2.0.1 ./depmod 2>&1`" = "Version requires old depmod, but couldn't run ./depmod.old: No such file or directory" ]
[ "`MODTEST_UNAME=2.4.20 ./depmod 2>&1`" = "Version requires old depmod, but couldn't run ./depmod.old: No such file or directory" ]
[ "`MODTEST_UNAME=2.4.49 ./depmod 2>&1`" = "Version requires old depmod, but couldn't run ./depmod.old: No such file or directory" ]

# Create one for it to find, put it in the path.
echo '#! /bin/sh' > tests/tmp/depmod.old
echo 'echo -n DEPMOD.OLD' >> tests/tmp/depmod.old
echo "for f; do echo -n \ \'\$f\'; done" >> tests/tmp/depmod.old
chmod a+x tests/tmp/depmod.old
PATH=`pwd`/tests/tmp:$PATH

MODTEST_UNAME=2.4.20

# If explicit path given, shouldn't search path.
[ "`./depmod 2>&1`" = "Version requires old depmod, but couldn't run ./depmod.old: No such file or directory" ]

# No args expected
[ "`depmod 2>&1`" = "DEPMOD.OLD" ]

# Args intact
[ "`depmod --some-wierd-option foo 2>&1`" = "DEPMOD.OLD '--some-wierd-option' 'foo'" ]

# Don't treat arg after -C as version number.
[ "`depmod -C 2.6.1 2>&1`" = "DEPMOD.OLD '-C' '2.6.1'" ]

# This should skip the arg after -C, and NOT invoke backwards compat code.
MODTEST_OVERRIDE1=/lib/modules/2.6.1-kexec
MODTEST_OVERRIDE_WITH1=DOES_NOT_EXIST
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

[ "`depmod -ae -C /dev/null 2.6.1-kexec 2>&1`" = "WARNING: Couldn't open directory /lib/modules/2.6.1-kexec: No such file or directory
FATAL: Could not open /lib/modules/2.6.1-kexec/modules.dep.temp for writing: No such file or directory" ]
