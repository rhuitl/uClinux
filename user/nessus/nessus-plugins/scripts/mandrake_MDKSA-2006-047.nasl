#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:047
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20981);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0709");
 
 name["english"] = "MDKSA-2006:047: metamail";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:047 (metamail).



Ulf Harnhammar discovered a buffer overflow vulnerability in the way that
metamail handles certain mail messages. An attacker could create a
carefully-crafted message that, when parsed via metamail, could execute
arbitrary code with the privileges of the user running metamail. The updated
packages have been patched to address this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:047
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the metamail package";
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
if ( rpm_check( reference:"metamail-2.7-11.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"metamail-2.7-11.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"metamail-2.7-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"metamail-", release:"MDK10.1")
 || rpm_exists(rpm:"metamail-", release:"MDK10.2")
 || rpm_exists(rpm:"metamail-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-0709", value:TRUE);
}
