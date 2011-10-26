#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:063
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17669);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0085");
 
 name["english"] = "MDKSA-2005:063: htdig";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:063 (htdig).



A cross-site scripting vulnerability in ht://dig was discovered by Michael
Krax. The updated packages have been patched to correct this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:063
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the htdig package";
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
if ( rpm_check( reference:"htdig-3.2.0-0.8.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"htdig-devel-3.2.0-0.8.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"htdig-web-3.2.0-0.8.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"htdig-3.2.0-0.8.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"htdig-devel-3.2.0-0.8.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"htdig-web-3.2.0-0.8.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"htdig-", release:"MDK10.0")
 || rpm_exists(rpm:"htdig-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-0085", value:TRUE);
}
