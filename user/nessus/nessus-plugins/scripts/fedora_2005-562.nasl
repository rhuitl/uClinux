#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19197);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1740", "CVE-2005-2177");
 
 name["english"] = "Fedora Core 3 2005-562: net-snmp";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-562 (net-snmp).

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
-without tcp_wrappers : disable tcp_wrappers support


* Wed Jul 13 2005 Radek Vokal

- CVE-2005-2177 new upstream version fixing DoS (#162908)
- CVE-2005-1740 net-snmp insecure temporary file usage (#158770)
- session free fixed, agentx modules build fine (#157851)
- report gigabit Ethernet speeds using Ethtool (#152480)



Solution : http://www.fedoranews.org/blog/index.php?p=755
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
if ( rpm_check( reference:"net-snmp-5.2.1.2-FC3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-utils-5.2.1.2-FC3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-devel-5.2.1.2-FC3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-perl-5.2.1.2-FC3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-libs-5.2.1.2-FC3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-debuginfo-5.2.1.2-FC3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"net-snmp-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-1740", value:TRUE);
 set_kb_item(name:"CVE-2005-2177", value:TRUE);
}
