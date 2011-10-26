#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:075
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13974);
 script_bugtraq_id(4679);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0374", "CVE-2002-0825");
 
 name["english"] = "MDKSA-2002:075: nss_ldap";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:075 (nss_ldap).


A buffer overflow vulnerability exists in nss_ldap versions prior to 198. When
nss_ldap is configured without a value for the 'host' keyword, it attempts to
configure itself using SRV records stored in DNS. nss_ldap does not check that
the data returned by the DNS query will fit into an internal buffer, thus
exposing it to an overflow.
A similar issue exists in versions of nss_ldap prior to 199 where nss_ldap does
not check that the data returned by the DNS query has not been truncated by the
resolver libraries to avoid a buffer overflow. This can make nss_ldap attempt to
parse more data than what is actually available, making it vulnerable to a read
buffer overflow.
Finally, a format string bug in the logging function of pam_ldap prior to
version 144 exist.
All users are recommended to upgrade to these updated packages. Note that the
nss_ldap packages for 7.2, 8.0, and Single Network Firewall 7.2 contain the
pam_ldap modules.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:075
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the nss_ldap package";
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
if ( rpm_check( reference:"nss_ldap-202-1.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nss_ldap-202-1.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nss_ldap-202-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pam_ldap-156-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nss_ldap-202-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pam_ldap-156-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nss_ldap-202-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pam_ldap-156-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"nss_ldap-", release:"MDK7.2")
 || rpm_exists(rpm:"nss_ldap-", release:"MDK8.0")
 || rpm_exists(rpm:"nss_ldap-", release:"MDK8.1")
 || rpm_exists(rpm:"nss_ldap-", release:"MDK8.2")
 || rpm_exists(rpm:"nss_ldap-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-0374", value:TRUE);
 set_kb_item(name:"CVE-2002-0825", value:TRUE);
}
