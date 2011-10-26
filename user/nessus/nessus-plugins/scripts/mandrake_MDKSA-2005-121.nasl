#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:121
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19226);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2069");
 
 name["english"] = "MDKSA-2005:121: nss_ldap";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:121 (nss_ldap).



Rob Holland, of the Gentoo Security Audit Team, discovered that pam_ldap and
nss_ldap would not use TLS for referred connections if they are referred to a
master after connecting to a slave, regardless of the 'ssl start_tls' setting
in ldap.conf.

As well, a bug in nss_ldap in Corporate Server and Mandrake 10.0 has been fixed
that caused crond, and other applications, to crash as a result of clients
receiving a SIGPIPE signal when attempting to issue a new search request to a
directory server that is no longer available.

The updated packages have been patched to address this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:121
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
if ( rpm_check( reference:"nss_ldap-212-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pam_ldap-167-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nss_ldap-220-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pam_ldap-170-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nss_ldap-220-5.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pam_ldap-170-5.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"nss_ldap-", release:"MDK10.0")
 || rpm_exists(rpm:"nss_ldap-", release:"MDK10.1")
 || rpm_exists(rpm:"nss_ldap-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2069", value:TRUE);
}
