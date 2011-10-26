#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:134
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19893);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2097");
 
 name["english"] = "MDKSA-2005:134: xpdf";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:134 (xpdf).



A vulnerability in the xpdf PDF viewer was discovered. An attacker could
construct a malicious PDF file that would cause xpdf to consume all available
disk space in /tmp when opened.

The updated packages have been patched to correct this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:134
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xpdf package";
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
if ( rpm_check( reference:"xpdf-3.00-7.5.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xpdf-3.00pl3-6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"xpdf-", release:"MDK10.1")
 || rpm_exists(rpm:"xpdf-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2097", value:TRUE);
}
