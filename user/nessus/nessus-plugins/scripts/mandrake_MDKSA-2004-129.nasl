#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:129
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15697);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0980");
 
 name["english"] = "MDKSA-2004:129: ez-ipupdate";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:129 (ez-ipupdate).



Ulf Harnhammar discovered a format string vulnerability in ez-ipupdate, a
client for many dynamic DNS services. The updated packages are patched to
protect against this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:129
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ez-ipupdate package";
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
if ( rpm_check( reference:"ez-ipupdate-3.0.11b8-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ez-ipupdate-3.0.11b8-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ez-ipupdate-3.0.11b8-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ez-ipupdate-", release:"MDK10.0")
 || rpm_exists(rpm:"ez-ipupdate-", release:"MDK10.1")
 || rpm_exists(rpm:"ez-ipupdate-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0980", value:TRUE);
}
