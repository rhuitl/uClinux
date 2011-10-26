#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:187
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20432);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2966");
 
 name["english"] = "MDKSA-2005:187: dia";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:187 (dia).



Joxean Koret discovered that the Python SVG import plugin in dia, a
vector-oriented diagram editor, does not properly sanitise data read from an
SVG file and is hence vulnerable to execute arbitrary Python code.

The updated packages have been patched to address this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:187
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the dia package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"dia-0.94-4.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dia-0.94-6.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"dia-", release:"MDK10.2")
 || rpm_exists(rpm:"dia-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-2966", value:TRUE);
}
