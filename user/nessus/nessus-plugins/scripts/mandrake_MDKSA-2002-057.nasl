#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:057
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13958);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0015");
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0391");
 
 name["english"] = "MDKSA-2002:057: krb5";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:057 (krb5).


The network authentication system in Kerberos 5 contains an RPC library that
includes an XDR decoder derived from Sun's RPC implementation. This
implemenation is vulnerable to a heap overflow. With Kerberos, it is believed
that an attacker would need to be able to successfully authenticate to kadmin to
be able to exploit this vulnerability.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:057
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
if ( rpm_check( reference:"ftp-client-krb5-1.2.2-17.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ftp-server-krb5-1.2.2-17.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-devel-1.2.2-17.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.2-17.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.2-17.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.2-17.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-client-krb5-1.2.2-17.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-server-krb5-1.2.2-17.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ftp-client-krb5-1.2.2-17.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ftp-server-krb5-1.2.2-17.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-devel-1.2.2-17.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.2-17.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.2-17.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.2-17.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-client-krb5-1.2.2-17.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-server-krb5-1.2.2-17.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"krb5-", release:"MDK8.1")
 || rpm_exists(rpm:"krb5-", release:"MDK8.2") )
{
 set_kb_item(name:"CVE-2002-0391", value:TRUE);
}
