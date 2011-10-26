#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:047
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17216);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0446");
 
 name["english"] = "MDKSA-2005:047: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:047 (squid).



The squid developers discovered that a remote attacker could cause squid to
crash via certain DNS responses.

The updated packages are patched to fix the problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:047
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the squid package";
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
if ( rpm_check( reference:"squid-2.5.STABLE4-2.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE6-2.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE3-3.7.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"squid-", release:"MDK10.0")
 || rpm_exists(rpm:"squid-", release:"MDK10.1")
 || rpm_exists(rpm:"squid-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2005-0446", value:TRUE);
}
