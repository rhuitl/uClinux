#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:123
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19267);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2317");
 
 name["english"] = "MDKSA-2005:123: shorewall";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:123 (shorewall).



A vulnerability was discovered in all versions of shorewall where a client
accepted by MAC address filtering is able to bypass any other rule. If
MACLIST_TTL is set to a value greater than 0 or MACLIST_DISPOSITION is set to
ACCEPT in shorewall.conf, and a client is positively identified through its MAC
address, it bypasses all other policies and rules in place, gaining access to
all open services on the firewall.

Shorewall 2.0.17 is provided which fixes this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:123
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the shorewall package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"shorewall-2.0.17-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"shorewall-doc-2.0.17-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"shorewall-2.0.17-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"shorewall-doc-2.0.17-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"shorewall-2.0.17-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"shorewall-doc-2.0.17-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"shorewall-", release:"MDK10.0")
 || rpm_exists(rpm:"shorewall-", release:"MDK10.1")
 || rpm_exists(rpm:"shorewall-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2317", value:TRUE);
}
