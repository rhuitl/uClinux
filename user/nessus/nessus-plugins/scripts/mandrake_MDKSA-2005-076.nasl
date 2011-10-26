#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:076
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18106);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0638", "CVE-2005-0639");
 
 name["english"] = "MDKSA-2005:076: xli";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:076 (xli).



A number of vulnerabilities have been found in the xli image viewer. Tavis
Ormandy of the Gentoo Linux Security Audit Team discovered a flaw in the
handling of compressed images where shell meta-characters are not properly
escaped (CVE-2005-0638). It was also found that insufficient validation of
image properties could potentially result in buffer management errors
(CVE-2005-0639).

The updated packages have been patched to correct these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:076
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xli package";
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
if ( rpm_check( reference:"xli-1.17.0-8.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xli-1.17.0-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"xli-", release:"MDK10.1")
 || rpm_exists(rpm:"xli-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-0638", value:TRUE);
 set_kb_item(name:"CVE-2005-0639", value:TRUE);
}
