#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:117
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19191);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-1848");
 
 name["english"] = "MDKSA-2005:117: dhcpcd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:117 (dhcpcd).



'infamous42md' discovered that the dhcpcd DHCP client could be tricked into
reading past the end of the supplied DHCP buffer, which could lead to the
daemon crashing.

The updated packages have been patched to address this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:117
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the dhcpcd package";
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
if ( rpm_check( reference:"dhcpcd-1.3.22pl4-4.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcpcd-1.3.22pl4-4.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"dhcpcd-", release:"MDK10.1")
 || rpm_exists(rpm:"dhcpcd-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1848", value:TRUE);
}
