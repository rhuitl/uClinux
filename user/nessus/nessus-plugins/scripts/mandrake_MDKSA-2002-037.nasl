#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:037
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13942);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2002:037: dhcp";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:037 (dhcp).


Fermin J. Serna discovered a problem in the dhcp server and client package from
versions 3.0 to 3.0.1rc8, which are affected by a format string vulnerability
that can be exploited remotely. By default, these versions of DHCP are compiled
with the dns update feature enabled, which allows DHCP to update DNS records.
The code that logs this update has an exploitable format string vulnerability;
the update message can contain data provided by the attacker, such as a
hostname. A successful exploitation could give the attacker elevated privileges
equivalent to the user running the DHCP daemon, which is the user dhcpd in
Mandrake Linux 8.x, but root in earlier versions.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:037
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
if ( rpm_check( reference:"dhcp-3.0b2pl9-4.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-client-3.0b2pl9-4.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-relay-3.0b2pl9-4.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-client-3.0-0.rc12.2.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-common-3.0-0.rc12.2.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-devel-3.0-0.rc12.2.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-relay-3.0-0.rc12.2.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-server-3.0-0.rc12.2.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-client-3.0-1rc8.2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-common-3.0-1rc8.2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-devel-3.0-1rc8.2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-relay-3.0-1rc8.2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-server-3.0-1rc8.2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
