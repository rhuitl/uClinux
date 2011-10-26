#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:054
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17332);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0373");
 
 name["english"] = "MDKSA-2005:054: cyrus-sasl";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:054 (cyrus-sasl).



A buffer overflow was discovered in cyrus-sasl's digestmd5 code. This could
lead to a remote attacker executing code in the context of the service using
SASL authentication. This vulnerability was fixed upstream in version 2.1.19.

The updated packages are patched to deal with this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:054
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cyrus-sasl package";
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
if ( rpm_check( reference:"cyrus-sasl-2.1.15-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-2.1.15-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-devel-2.1.15-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-anonymous-2.1.15-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-crammd5-2.1.15-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-digestmd5-2.1.15-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-gssapi-2.1.15-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-login-2.1.15-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-ntlm-2.1.15-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-otp-2.1.15-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-plain-2.1.15-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-sasldb-2.1.15-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-srp-2.1.15-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cyrus-sasl-", release:"MDK10.0") )
{
 set_kb_item(name:"CVE-2005-0373", value:TRUE);
}
