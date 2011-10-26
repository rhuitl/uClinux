#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:119
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19201);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0027");
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0175", "CVE-2005-0488", "CVE-2005-1174", "CVE-2005-1175", "CVE-2005-1689");
 
 name["english"] = "MDKSA-2005:119: krb5";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:119 (krb5).



A number of vulnerabilities have been corrected in this Kerberos update:

The rcp protocol would allow a server to instruct a client to write to
arbitrary files outside of the current directory. The Kerberos-aware rcp could
be abused to copy files from a malicious server (CVE-2004-0175).

Gael Delalleau discovered an information disclosure vulnerability in the way
some telnet clients handled messages from a server. This could be abused by a
malicious telnet server to collect information from the environment of any
victim connecting to the server using the Kerberos- aware telnet client
(CVE-2005-0488).

Daniel Wachdorf disovered that in error conditions that could occur in response
to correctly-formatted client requests, the Kerberos 5 KDC may attempt to free
uninitialized memory, which could cause the KDC to crash resulting in a Denial
of Service (CVE-2005-1174).

Daniel Wachdorf also discovered a single-byte heap overflow in the
krb5_unparse_name() function that could, if successfully exploited, lead to a
crash, resulting in a DoS. To trigger this flaw, an attacker would need to have
control of a Kerberos realm that shares a cross- realm key with the target
(CVE-2005-1175).

Finally, a double-free flaw was discovered in the krb5_recvauth() routine which
could be triggered by a remote unauthenticated attacker. This issue could
potentially be exploited to allow for the execution of arbitrary code on a KDC.
No exploit is currently known to exist (CVE-2005-1689).

The updated packages have been patched to address this issue and Mandriva urges
all users to upgrade to these packages as quickly as possible.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:119
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the krb5 package";
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
if ( rpm_check( reference:"ftp-client-krb5-1.3-6.6.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ftp-server-krb5-1.3-6.6.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.3-6.6.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.3-6.6.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkrb51-1.3-6.6.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkrb51-devel-1.3-6.6.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-client-krb5-1.3-6.6.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-server-krb5-1.3-6.6.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ftp-client-krb5-1.3.4-2.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ftp-server-krb5-1.3.4-2.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.3.4-2.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.3.4-2.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkrb53-1.3.4-2.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkrb53-devel-1.3.4-2.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-client-krb5-1.3.4-2.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-server-krb5-1.3.4-2.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ftp-client-krb5-1.3.6-6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ftp-server-krb5-1.3.6-6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.3.6-6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.3.6-6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkrb53-1.3.6-6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkrb53-devel-1.3.6-6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-client-krb5-1.3.6-6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-server-krb5-1.3.6-6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"krb5-", release:"MDK10.0")
 || rpm_exists(rpm:"krb5-", release:"MDK10.1")
 || rpm_exists(rpm:"krb5-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2004-0175", value:TRUE);
 set_kb_item(name:"CVE-2005-0488", value:TRUE);
 set_kb_item(name:"CVE-2005-1174", value:TRUE);
 set_kb_item(name:"CVE-2005-1175", value:TRUE);
 set_kb_item(name:"CVE-2005-1689", value:TRUE);
}
