#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:126
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15637);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-1001");
 
 name["english"] = "MDKSA-2004:126: shadow-utils";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:126 (shadow-utils).



A vulnerability in the shadow suite was discovered by Martin Schulze that can
be exploited by local users to bypass certain security restrictions due to an
input validation error in the passwd_check() function. This function is used by
the chfn and chsh tools.

The updated packages have been patched to prevent this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:126
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the shadow-utils package";
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
if ( rpm_check( reference:"shadow-utils-4.0.3-8.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"shadow-utils-4.0.3-8.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"shadow-utils-4.0.3-5.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"shadow-utils-", release:"MDK10.0")
 || rpm_exists(rpm:"shadow-utils-", release:"MDK10.1")
 || rpm_exists(rpm:"shadow-utils-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-1001", value:TRUE);
}
