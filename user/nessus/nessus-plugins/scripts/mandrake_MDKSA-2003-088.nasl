#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:088
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14070);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0734");
 
 name["english"] = "MDKSA-2003:088: pam_ldap";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:088 (pam_ldap).


A bug was fixed in pam_ldap 162 with the pam_filter mechanism which is commonly
used for host-based access restriction in environments using LDAP for
authentication. Mandrake Linux 9.1 provided pam_ldap 161 which had this problem
and as a result, systems relying on pam_filter for host-based access restriction
would allow any user, regardless of the host attribute associated with their
account, to log into the system. All users who use LDAP-based authentication are
encouraged to upgrade immediately.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:088
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the pam_ldap package";
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
if ( rpm_check( reference:"nss_ldap-207-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pam_ldap-164-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"pam_ldap-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0734", value:TRUE);
}
