#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:046-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13949);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2002-0655", "CVE-2002-0656", "CVE-2002-0657");
 
 name["english"] = "MDKSA-2002:046-1: openssl";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:046-1 (openssl).


An audit of the OpenSSL code by A.L. Digital Ltd and The Bunker, under the DARPA
program CHATS, discovered a number of vulnerabilities in the OpenSSL code that
are all potentially remotely exploitable.
From the OpenSSL advisory:
1. The client master key in SSL2 could be oversized and overrun a buffer. This
vulnerability was also independently discovered by consultants at Neohapsis
(http://www.neohapsis.com/) who have also demonstrated that the vulerability is
exploitable. Exploit code is NOT available at this time.
2. The session ID supplied to a client in SSL3 could be oversized and overrun a
buffer.
3. The master key supplied to an SSL3 server could be oversized and overrun a
stack-based buffer. This issues only affects OpenSSL 0.9.7 with Kerberos
enabled.
4. Various buffers for ASCII representations of integers were too small on 64
bit platforms.
At the same time, various potential buffer overflows have had assertions added;
these are not known to be exploitable.
Finally, a vulnerability was found by Adi Stav and James Yonan independantly in
the ASN1 parser which can be confused by supplying it with certain invalid
encodings. There are no known exploits for this vulnerability.
All of these vulnerabilities are fixed in OpenSSL 0.9.6f. Patches have been
applied to the versions of OpenSSL provided in this update to fix all of these
problems, except for the ASN1 vulnerability, which a fix will be provided for
once MandrakeSoft has had a chance to QA the new packages. In the meantime, it
is is strongly encouraged that all users upgrade to these OpenSSL packages.
Update:
These new OpenSSL packages are available to additionally fix the ASN1
vulnerability described above. All Mandrake Linux users are encouraged to
upgrade to these new packages.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:046-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openssl package";
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
if ( rpm_check( reference:"openssl-0.9.5a-4.4mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.5a-4.4mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.5a-9.3mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.5a-9.3mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6-8.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6-8.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-0.9.6b-1.3mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-devel-0.9.6b-1.3mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6b-1.3mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-0.9.6c-2.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-devel-0.9.6c-2.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6c-2.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"openssl-", release:"MDK7.1")
 || rpm_exists(rpm:"openssl-", release:"MDK7.2")
 || rpm_exists(rpm:"openssl-", release:"MDK8.0")
 || rpm_exists(rpm:"openssl-", release:"MDK8.1")
 || rpm_exists(rpm:"openssl-", release:"MDK8.2") )
{
 set_kb_item(name:"CVE-2002-0655", value:TRUE);
 set_kb_item(name:"CVE-2002-0656", value:TRUE);
 set_kb_item(name:"CVE-2002-0657", value:TRUE);
}
