#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:017
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16254);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0064");
 
 name["english"] = "MDKSA-2005:017: xpdf";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:017 (xpdf).



A buffer overflow vulnerability was discovered in the xpdf PDF viewer, which
could allow for arbitrary code execution as the user viewing a PDF file. The
vulnerability exists due to insufficient bounds checking while processing a PDF
file that provides malicious values in the /Encrypt /Length tag.

The updated packages have been patched to prevent these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:017
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
if ( rpm_check( reference:"xpdf-3.00-5.4.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xpdf-3.00-7.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"xpdf-", release:"MDK10.0")
 || rpm_exists(rpm:"xpdf-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-0064", value:TRUE);
}
