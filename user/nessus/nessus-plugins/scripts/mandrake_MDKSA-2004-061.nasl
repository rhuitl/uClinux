#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:061
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14160);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0018");
 script_bugtraq_id(10591);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2004-0460", "CVE-2004-0461");
 
 name["english"] = "MDKSA-2004:061: dhcp";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:061 (dhcp).


A vulnerability in how ISC's DHCPD handles syslog messages can allow a malicious
attacker with the ability to send special packets to the DHCPD listening port to
crash the daemon, causing a Denial of Service. It is also possible that they may
be able to execute arbitrary code on the vulnerable server with the permissions
of the user running DHCPD, which is usually root.
A similar vulnerability also exists in the way ISC's DHCPD makes use of the
vsnprintf() function on system that do not support vsnprintf(). This
vulnerability could also be used to execute arbitrary code and/or perform a DoS
attack. The vsnprintf() statements that have this problem are defined after the
vulnerable code noted above, which would trigger the previous problem rather
than this one.
Thanks to Gregory Duchemin and Solar Designer for discovering these flaws.
The updated packages contain 3.0.1rc14 which is not vulnerable to these
problems. Only ISC DHCPD 3.0.1rc12 and 3.0.1rc13 are vulnerable to these issues.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:061
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the dhcp package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"dhcp-client-3.0-1.rc14.0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-common-3.0-1.rc14.0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-devel-3.0-1.rc14.0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-relay-3.0-1.rc14.0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-server-3.0-1.rc14.0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-client-3.0-1.rc14.0.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-common-3.0-1.rc14.0.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-devel-3.0-1.rc14.0.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-relay-3.0-1.rc14.0.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-server-3.0-1.rc14.0.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"dhcp-", release:"MDK10.0")
 || rpm_exists(rpm:"dhcp-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0460", value:TRUE);
 set_kb_item(name:"CVE-2004-0461", value:TRUE);
}
