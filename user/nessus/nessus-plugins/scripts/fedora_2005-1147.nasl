#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20323);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "Fedora Core 4 2005-1147: sudo";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-1147 (sudo).

Sudo (superuser do) allows a system administrator to give certain
users (or groups of users) the ability to run some (or all) commands
as root while logging all commands and arguments. Sudo operates on a
per-command basis.  It is not a replacement for the shell.  Features
include: the ability to restrict what commands a user may run on a
per-host basis, copious logging of each command (providing a clear
audit trail of who did what), a configurable timeout of the sudo
command, and the ability to use the same configuration file (sudoers)
on many different machines.


* Sat Dec 16 2006 Karel Zak <kzak redhat com> 1.6.8p8-2.4
- fix #175295 - SECURITY: CRM 764618: Perl scripts run via Sudo can be subverte
d




Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sudo package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"sudo-1.6.8p8-2.4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
