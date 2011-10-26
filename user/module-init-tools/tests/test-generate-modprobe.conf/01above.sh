#! /bin/sh
# Test conversion of "above" command.

# Single arg.
echo 'above scsi_mod ide-scsi' > tests/tmp/modules.conf

TESTING_MODPROBE_CONF=tests/tmp/modules.conf
export TESTING_MODPROBE_CONF

[ "`generate-modprobe.conf > tests/tmp/modprobe.conf 2>&1`" = "" ]

[ `grep -v '^#' < tests/tmp/modprobe.conf | wc -l` = 2 ]

[ "`grep ^install tests/tmp/modprobe.conf`" = "install scsi_mod /sbin/modprobe --first-time --ignore-install scsi_mod && { /sbin/modprobe ide-scsi; /bin/true; }" ]

[ "`grep ^remove tests/tmp/modprobe.conf`" = "remove scsi_mod { /sbin/modprobe -r ide-scsi; } ; /sbin/modprobe -r --first-time --ignore-remove scsi_mod" ]

# Multiple arg.
echo 'above mod a b c' > tests/tmp/modules.conf

[ "`generate-modprobe.conf > tests/tmp/modprobe.conf 2>&1`" = "" ]

[ `grep -v '^#' < tests/tmp/modprobe.conf | wc -l` = 2 ]

[ "`grep ^install tests/tmp/modprobe.conf`" = "install mod /sbin/modprobe --first-time --ignore-install mod && { /sbin/modprobe a; /sbin/modprobe b; /sbin/modprobe c; /bin/true; }" ]

[ "`grep ^remove tests/tmp/modprobe.conf`" = "remove mod { /sbin/modprobe -r a; /sbin/modprobe -r b; /sbin/modprobe -r c; } ; /sbin/modprobe -r --first-time --ignore-remove mod" ]

# This matches with test-modprobe/22recursiveinstall.sh
echo 'add above ip_conntrack ip_conntrack_ftp' > tests/tmp/modules.conf

[ "`generate-modprobe.conf > tests/tmp/modprobe.conf 2>&1`" = "" ]

[ `grep -v '^#' < tests/tmp/modprobe.conf | wc -l` = 2 ]

[ "`grep ^install tests/tmp/modprobe.conf`" = "install ip_conntrack /sbin/modprobe --first-time --ignore-install ip_conntrack && { /sbin/modprobe ip_conntrack_ftp; /bin/true; }" ]

