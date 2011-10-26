#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:035
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14019);
 script_bugtraq_id(7101, 7148);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0131", "CVE-2003-0147");
 
 name["english"] = "MDKSA-2003:035: openssl";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:035 (openssl).


Researchers discovered a timing-based attack on RSA keys that OpenSSL is
generally vulnerable to, unless RSA blinding is enabled. Patches from the
OpenSSL team have been applied to turn RSA blinding on by default.
An extension of the 'Bleichenbacher attack' on RSA with PKS #1 v1.5 padding as
used in SSL 3.0 and TSL 1.0 was also created by Czech cryptologists Vlastimil
Klima, Ondrej Pokorny, and Tomas Rosa. This attack requires the attacker to open
millions of SSL/TLS connections to the server they are attacking. This is done
because the server's behaviour when faced with specially crafted RSA ciphertexts
can reveal information that would in effect allow the attacker to perform a
single RSA private key operation on a ciphertext of their choice, using the
server's RSA key. Despite this, the server's RSA key is not compromised at any
time. Patches from the OpenSSL team modify SSL/TLS server behaviour to avoid
this vulnerability.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:035
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openssl package";
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
if ( rpm_check( reference:"openssl-0.9.5a-9.5mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.5a-9.5mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6i-1.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6i-1.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6i-1.4mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-0.9.6i-1.4mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-devel-0.9.6i-1.4mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6i-1.4mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-0.9.6i-1.4mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-devel-0.9.6i-1.4mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6i-1.4mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-0.9.6i-1.4mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-devel-0.9.6i-1.4mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7a-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-0.9.6i-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-0.9.7a-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-devel-0.9.7a-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"openssl-", release:"MDK7.2")
 || rpm_exists(rpm:"openssl-", release:"MDK8.0")
 || rpm_exists(rpm:"openssl-", release:"MDK8.1")
 || rpm_exists(rpm:"openssl-", release:"MDK8.2")
 || rpm_exists(rpm:"openssl-", release:"MDK9.0")
 || rpm_exists(rpm:"openssl-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0131", value:TRUE);
 set_kb_item(name:"CVE-2003-0147", value:TRUE);
}
