#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:088
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14673);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0027");
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0642", "CVE-2004-0643", "CVE-2004-0644", "CVE-2004-0772");
 
 name["english"] = "MDKSA-2004:088: krb5";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:088 (krb5).


A double-free vulnerability exists in the MIT Kerberos 5's KDC program that
could potentially allow a remote attacker to execute arbitrary code on the KDC
host. As well, multiple double-free vulnerabilities exist in the krb5 library
code, which makes client programs and application servers vulnerable. The MIT
Kerberos 5 development team believes that exploitation of these bugs would be
difficult and no known vulnerabilities are believed to exist. The vulnerability
in krb524d was discovered by Marc Horowitz; the other double-free
vulnerabilities were discovered by Will Fiveash and Nico Williams at Sun.
Will Fiveash and Nico Williams also found another vulnerability in the ASN.1
decoder library. This makes krb5 vulnerable to a DoS (Denial of Service) attack
causing an infinite loop in the decoder. The KDC is vulnerable to this attack.
The MIT Kerberos 5 team has provided patches which have been applied to the
updated software to fix these issues. Mandrakesoft encourages all users to
upgrade immediately.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:088
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the krb5 package";
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
if ( rpm_check( reference:"ftp-client-krb5-1.3-6.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ftp-server-krb5-1.3-6.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.3-6.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.3-6.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkrb51-1.3-6.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkrb51-devel-1.3-6.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-client-krb5-1.3-6.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-server-krb5-1.3-6.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ftp-client-krb5-1.2.7-1.4.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ftp-server-krb5-1.2.7-1.4.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-devel-1.2.7-1.4.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.7-1.4.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.7-1.4.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.7-1.4.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-client-krb5-1.2.7-1.4.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-server-krb5-1.2.7-1.4.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ftp-client-krb5-1.3-3.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ftp-server-krb5-1.3-3.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.3-3.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.3-3.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkrb51-1.3-3.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkrb51-devel-1.3-3.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-client-krb5-1.3-3.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-server-krb5-1.3-3.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"krb5-", release:"MDK10.0")
 || rpm_exists(rpm:"krb5-", release:"MDK9.1")
 || rpm_exists(rpm:"krb5-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0642", value:TRUE);
 set_kb_item(name:"CVE-2004-0643", value:TRUE);
 set_kb_item(name:"CVE-2004-0644", value:TRUE);
 set_kb_item(name:"CVE-2004-0772", value:TRUE);
}
