#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20100);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CAN-2005-1704", "CAN-2005-1705");
 
 name["english"] = "Fedora Core 3 2005-1032: gdb";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-1032 (gdb).

GDB, the GNU debugger, allows you to debug programs written in C, C++,
and other languages, by executing them in a controlled fashion and
printing their data.

Update Information:

This is an fc3 update for gdb regarding security issues:

CAN-2005-1704 Integer Overflow in gdb

This problem is that gdb's internal copy of bfd
does not protect against heap-based overflow.

CAN-2005-1705 gdb arbitrary command execution

This problem allows unprotected .gdbinit files
to execute arbitrary commands during gdb startup.

Fixes for both problems are found in:

gdb-6.1post-1.20040607.43.0.1




Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gdb package";
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
if ( rpm_check( reference:"gdb-6.1post-1.20040607.43.0.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"gdb-", release:"FC3") )
{
 set_kb_item(name:"CAN-2005-1704", value:TRUE);
 set_kb_item(name:"CAN-2005-1705", value:TRUE);
}
