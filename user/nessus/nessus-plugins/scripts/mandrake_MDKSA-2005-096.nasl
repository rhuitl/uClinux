#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:096
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18434);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0109");
 
 name["english"] = "MDKSA-2005:096: openssl";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:096 (openssl).



Colin Percival reported a cache timing attack that could be used to allow a
malicious local user to gain portions of cryptographic keys (CVE-2005-0109).
The OpenSSL library has been patched to add a new fixed-window mod_exp
implementation as default for RSA, DSA, and DH private key operations. The
patch was designed to mitigate cache timing and possibly related attacks.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:096
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openssl package";
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
if ( rpm_check( reference:"libopenssl0.9.7-0.9.7c-3.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-devel-0.9.7c-3.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-static-devel-0.9.7c-3.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7c-3.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-0.9.7d-1.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-devel-0.9.7d-1.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-static-devel-0.9.7d-1.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7d-1.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-0.9.7e-5.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-devel-0.9.7e-5.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-static-devel-0.9.7e-5.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7e-5.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"openssl-", release:"MDK10.0")
 || rpm_exists(rpm:"openssl-", release:"MDK10.1")
 || rpm_exists(rpm:"openssl-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-0109", value:TRUE);
}
