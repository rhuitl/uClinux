#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:190
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20120);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2641");
 
 name["english"] = "MDKSA-2005:190: nss_ldap";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:190 (nss_ldap).



A bug was found in the way the pam_ldap module processed certain failure
messages. If the server includes supplemental data in an authentication failure
result message, but the data does not include any specific error code, the
pam_ldap module would proceed as if the authentication request had succeeded,
and authentication would succeed. This affects versions 169 through 179 of
pam_ldap.

The updated packages have been patched to address this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:190
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the nss_ldap package";
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
if ( rpm_check( reference:"nss_ldap-220-3.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pam_ldap-170-3.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pam_ldap-170-5.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nss_ldap-220-5.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"nss_ldap-", release:"MDK10.1")
 || rpm_exists(rpm:"nss_ldap-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2641", value:TRUE);
}
