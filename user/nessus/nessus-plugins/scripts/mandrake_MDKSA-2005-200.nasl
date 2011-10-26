#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:200
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20126);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2963");
 
 name["english"] = "MDKSA-2005:200: apache-mod_auth_shadow";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:200 (apache-mod_auth_shadow).



The mod_auth_shadow module 1.0 through 1.5 and 2.0 for Apache with AuthShadow
enabled uses shadow authentication for all locations that use the require group
directive, even when other authentication mechanisms are specified, which might
allow remote authenticated users to bypass security restrictions. This update
requires an explicit 'AuthShadow on' statement if website authentication should
be checked against /etc/shadow. The updated packages have been patched to
address this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:200
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the apache-mod_auth_shadow package";
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
if ( rpm_check( reference:"apache2-mod_auth_shadow-2.0.50_2.0-3.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_auth_shadow-2.0.53_2.0-6.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-mod_auth_shadow-2.0.54_2.0-4.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"apache-mod_auth_shadow-", release:"MDK10.1")
 || rpm_exists(rpm:"apache-mod_auth_shadow-", release:"MDK10.2")
 || rpm_exists(rpm:"apache-mod_auth_shadow-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-2963", value:TRUE);
}
