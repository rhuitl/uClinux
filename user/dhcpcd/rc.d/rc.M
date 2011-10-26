#!/bin/sh
#
# rc.M		This file is executed by init(8) when the system is being
#		initialized for one of the "multi user" run levels (i.e.
#		levels 1 through 6).  It usually does mounting of file
#		systems et al.
#
# Version:	@(#)/etc/rc.d/rc.M	2.02	02/26/93
#
# Author:	Fred N. van Kempen, <waltje@uwalt.nl.mugnet.org>
#		Heavily modified by Patrick Volkerding <volkerdi@ftp.cdrom.com>
#
# Modified:     Yoichi Hariguchi <yoichi@fore.com>  09/14/96
#
#

# Tell the viewers what's going to happen...
echo "Going multiuser..."

# Screen blanks after 15 minutes idle time.
/bin/setterm -blank 15

# Look for a CD-ROM in a CD-ROM drive, and if one is found,
# mount it under /cdrom.  This must happen before any of the
# binaries on the CD are needed.
if [ -r /etc/rc.d/rc.cdrom ]; then
  . /etc/rc.d/rc.cdrom
fi

# Start crond (Dillon's crond):
# If you want cron to actually log activity to /var/adm/cron, then change
# -l10 to -l8 to increase the logging level.
# /usr/sbin/crond -l10 >>/var/adm/cron 2>&1

# If there's no /etc/HOSTNAME, fall back on this default:
if [ ! -r /etc/HOSTNAME ]; then
 echo "darkstar.frop.org" > /etc/HOSTNAME
fi

# Set the hostname.  This might not work correctly if TCP/IP is not 
# compiled in the kernel.
/bin/hostname `cat /etc/HOSTNAME | cut -f1 -d .`

# Initialize the NET subsystem.
if [ -x /etc/rc.d/rc.inet1 ]; then
  . /etc/rc.d/rc.inet1
  . /etc/rc.d/rc.inet2
else
  /usr/sbin/syslogd
  /usr/sbin/klogd
  /usr/sbin/lpd
fi

# Remove stale locks (must be done after mount -a!)
/bin/rm -f /var/spool/locks/* /var/spool/uucp/LCK..* /tmp/.X*lock 1> /dev/null 2> /dev/null

# Remove stale hunt sockets so the game can start.
if [ -r /tmp/hunt -o -r /tmp/hunt.stats ]; then
  echo "Removing your stale hunt sockets from /tmp..."
  /bin/rm -f /tmp/hunt*
fi

# Update all the shared library links automatically
/sbin/ldconfig

# Initialize PCMCIA devices:
if [ -x /etc/rc.d/rc.pcmcia ] ; then
  /etc/rc.d/rc.pcmcia start
fi


# Start the sendmail daemon:
#if [ -x /usr/sbin/sendmail ]; then
#  echo "Starting sendmail daemon (/usr/sbin/sendmail -bd -q 15m)..."
#  /usr/sbin/sendmail -bd -q 15m
#fi

# Load a custom screen font if the user has an rc.font script.
if [ -r /etc/rc.d/rc.font ]; then
  . /etc/rc.d/rc.font
fi

# iBCS Emulation for Linux
# The Intel Binary Compatibility Specification, or iBCS, specifies the
# interfaces between application programs and the surrounding operating
# system environment for i386 based systems. There are however several
# flavours of iBCS in use - SVR4, SVR3 plus several vendor specific
# extensions to SVR3 which are slightly different and incompatible. The
# iBCS emulator for Linux supports all flavours known so far.
if [ -r /usr/lib/modules/iBCS ]; then
  . /etc/rc.d/rc.ibcs2
fi

# Load a custom keymap if the user has an rc.keymap script.
if [ -r /etc/rc.d/rc.keymap ]; then
  . /etc/rc.d/rc.keymap
fi

# Start the local setup procedure.
if [ -f /etc/rc.d/rc.local ]; then
  . /etc/rc.d/rc.local
fi

# All done.
