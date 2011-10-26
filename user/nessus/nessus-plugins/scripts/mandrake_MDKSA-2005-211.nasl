#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:211
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20444);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2929");
 
 name["english"] = "MDKSA-2005:211: lynx";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:211 (lynx).



An arbitrary command execution vulnerability was discovered in the lynx
'lynxcgi:' URI handler. An attacker could create a web page that redirects to a
malicious URL which could then execute arbitrary code as the user running lynx.
The updated packages have been patched to address this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:211
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the lynx package";
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
if ( rpm_check( reference:"lynx-2.8.5-1.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lynx-2.8.5-1.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lynx-2.8.5-4.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"lynx-", release:"MDK10.1")
 || rpm_exists(rpm:"lynx-", release:"MDK10.2")
 || rpm_exists(rpm:"lynx-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-2929", value:TRUE);
}
