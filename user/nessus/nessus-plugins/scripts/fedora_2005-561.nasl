#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19190);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1740", "CVE-2005-2177");
 
 name["english"] = "Fedora Core 4 2005-561: net-snmp";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-561 (net-snmp).

SNMP (Simple Network Management Protocol) is a protocol used for
network management. The NET-SNMP project includes various SNMP tools:
an extensible agent, an SNMP library, tools for requesting or setting
information from SNMP agents, tools for generating and handling SNMP
traps, a version of the netstat command which uses SNMP, and a Tk/Perl
mib browser. This package contains the snmpd and snmptrapd daemons,
documentation, etc.

You will probably also want to install the net-snmp-utils package,
which contains NET-SNMP utilities.

Building option:
--without tcp_wrappers : disable tcp_wrappers support

Update Information:

A security vulnerability has been found in Net-SNMP releases that
could allow a denial of service attack against Net-SNMP agent's which
have opened a stream based protocol (EG, TCP but not UDP; it should be
noted that Net-SNMP does not by default open a TCP port).

http://sourceforge.net/mailarchive/forum.php?thread_id=7659656&forum_id=12455


Solution : http://fedoranews.org//mediawiki/index.php/Fedora_Core_4_Update:_net-snmp-5.2.1.2-fc4.1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the net-snmp package";
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
if ( rpm_check( reference:"net-snmp-5.2.1.2-fc4.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-utils-5.2.1.2-fc4.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-devel-5.2.1.2-fc4.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-perl-5.2.1.2-fc4.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-libs-5.2.1.2-fc4.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"net-snmp-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-1740", value:TRUE);
 set_kb_item(name:"CVE-2005-2177", value:TRUE);
}
