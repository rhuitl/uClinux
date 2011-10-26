#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:021
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14006);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0041");
 
 name["english"] = "MDKSA-2003:021: krb5";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:021 (krb5).


A vulnerability was discovered in the Kerberos FTP client. When the client
retrieves a file that has a filename beginning with a pipe character, the FTP
client will pass that filename to the command shell in a system() call. This
could allow a malicious remote FTP server to write to files outside of the
current directory or even execute arbitrary commands as the user using the FTP
client.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:021
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
if ( rpm_check( reference:"ftp-client-krb5-1.2.2-17.4mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ftp-server-krb5-1.2.2-17.4mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-devel-1.2.2-17.4mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.2-17.4mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.2-17.4mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.2-17.4mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-client-krb5-1.2.2-17.4mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-server-krb5-1.2.2-17.4mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ftp-client-krb5-1.2.2-17.4mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ftp-server-krb5-1.2.2-17.4mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-devel-1.2.2-17.4mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.2-17.4mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.2-17.4mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.2-17.4mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-client-krb5-1.2.2-17.4mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-server-krb5-1.2.2-17.4mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ftp-client-krb5-1.2.5-1.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ftp-server-krb5-1.2.5-1.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-devel-1.2.5-1.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.5-1.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.5-1.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.5-1.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-client-krb5-1.2.5-1.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-server-krb5-1.2.5-1.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"krb5-", release:"MDK8.1")
 || rpm_exists(rpm:"krb5-", release:"MDK8.2")
 || rpm_exists(rpm:"krb5-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0041", value:TRUE);
}
