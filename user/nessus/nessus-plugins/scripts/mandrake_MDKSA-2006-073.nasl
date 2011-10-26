#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:073
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21280);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-1721");
 
 name["english"] = "MDKSA-2006:073: cyrus-sasl";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:073 (cyrus-sasl).



A vulnerability in the CMU Cyrus Simple Authentication and Security Layer
(SASL) library < 2.1.21, has an unknown impact and remote unauthenticated
attack vectors, related to DIGEST-MD5 negotiation. In practice, Marcus Meissner
found it is possible to crash the cyrus-imapd daemon with a carefully crafted
communication that leaves out 'realm=...' in the reply or the initial server
response. Updated packages have been patched to address this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:073
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cyrus-sasl package";
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
if ( rpm_check( reference:"cyrus-sasl-2.1.19-12.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-2.1.19-12.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-devel-2.1.19-12.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-anonymous-2.1.19-12.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-crammd5-2.1.19-12.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-digestmd5-2.1.19-12.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-gssapi-2.1.19-12.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-login-2.1.19-12.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-ntlm-2.1.19-12.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-otp-2.1.19-12.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-plain-2.1.19-12.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-sasldb-2.1.19-12.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-sql-2.1.19-12.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl2-plug-srp-2.1.19-12.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cyrus-sasl-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2006-1721", value:TRUE);
}
