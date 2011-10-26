#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:106
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15435);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0884");
 
 name["english"] = "MDKSA-2004:106: cyrus-sasl";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:106 (cyrus-sasl).


A vulnerability was discovered in the libsasl library of cyrus-sasl. libsasl
honors the SASL_PATH environment variable blindly, which could allow a local
user to create a malicious 'library' that would get executed with the effective
ID of SASL when anything calls libsasl.
The provided packages are patched to protect against this vulnerability.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:106
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cyrus-sasl package";
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
if ( rpm_check( reference:"cyrus-sasl-2.1.15-10.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-2.1.15-10.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-devel-2.1.15-10.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-otp-2.1.15-10.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-srp-2.1.15-10.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-2.1.15-4.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-2.1.15-4.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-devel-2.1.15-4.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-gssapi-2.1.15-4.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-login-2.1.15-4.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-ntlm-2.1.15-4.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-otp-2.1.15-4.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-plain-2.1.15-4.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-sasldb-2.1.15-4.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-srp-2.1.15-4.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cyrus-sasl-", release:"MDK10.0")
 || rpm_exists(rpm:"cyrus-sasl-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0884", value:TRUE);
}
