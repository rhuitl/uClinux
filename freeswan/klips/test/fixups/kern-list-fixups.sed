s/tracing thread pid = \(.*\)/tracing thread pid = XXXXX/
s/spawn \(.*\) single/spawn PATH single/
s/Program invoked with \(.*\)\/start.sh/Program invoked with PATH\/start.sh/
s/Starting UML \(.*\)\/start.sh/Starting UML PATH\/start.sh/
s/Kernel command line: ubd0=.* ubd1=.* umid=.* eth0=.* eth1=.* .*/Kernel command line:/
s/mconsole initialized on .*/mconsole initialized on PATH/
s/Calculating module dependencies... .*/Calculating module dependancies/
s/Loading modules: .*/Loading modules: LIST/
/modprobe: /d
s/Calibrating delay loop... .*/Calibrating delay loop... XXXX bogomips/
s/Linux version .*/Linux version XXXX/
s/klips_info:ipsec_init: KLIPS startup, FreeS\/WAN IPSec version: .*/klips_info:ipsec_init: KLIPS startup, FreeS\/WAN IPSec version: XXXX/
/hostfs on /d
s/devfs: v.* Richard Gooch (rgooch@atnf.csiro.au)/devfs: VERSION Richard Gooch (rgooch@atnf.csiro.au)/
s/devfs: boot_options: .*/devfs: boot_options Q/
s/block: .*/block: slots and queues/
/INIT: can't open(.etc.ioctl.save, O_WRONLY): Permission denied/d
/VFS: Mounted root (root.hostfs filesystem) readonly./d







