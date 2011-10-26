#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18542);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1993");
 
 name["english"] = "Fedora Core 3 2005-472: sudo";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-472 (sudo).

Sudo (superuser do) allows a system administrator to give certain
users (or groups of users) the ability to run some (or all) commands
as root while logging all commands and arguments. Sudo operates on a
per-command basis. It is not a replacement for the shell. Features
include: the ability to restrict what commands a user may run on a
per-host basis, copious logging of each command (providing a clear
audit trail of who did what), a configurable timeout of the sudo
command, and the ability to use the same configuration file (sudoers)
on many different machines.


* Tue Jun 21 2005 Karel Zak 1.6.7p5-30.3

- fix #161116 - CVE-2005-1993 sudo trusted user arbitrary command
execution



Solution : http://www.fedoranews.org/blog/index.php?p=727
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
if ( rpm_check( reference:"sudo-1.6.7p5-30.3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sudo-debuginfo-1.6.7p5-30.3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"sudo-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-1993", value:TRUE);
}
