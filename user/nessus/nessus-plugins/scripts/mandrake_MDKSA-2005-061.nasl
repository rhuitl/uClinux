#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:061
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17658);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0468", "CVE-2005-0469");
 
 name["english"] = "MDKSA-2005:061: krb5";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:061 (krb5).



Two buffer overflow issues were discovered in the way telnet clients handle
messages from a server. Because of these issues, an attacker may be able to
execute arbitray code on the victim's machine if the victim can be tricked into
connecting to a malicious telnet server. The Kerberos package contains a telnet
client and is patched to deal with these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:061
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
if ( rpm_check( reference:"ftp-client-krb5-1.3-6.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ftp-server-krb5-1.3-6.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.3-6.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.3-6.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkrb51-1.3-6.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkrb51-devel-1.3-6.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-client-krb5-1.3-6.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-server-krb5-1.3-6.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ftp-client-krb5-1.3.4-2.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ftp-server-krb5-1.3.4-2.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.3.4-2.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.3.4-2.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkrb53-1.3.4-2.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkrb53-devel-1.3.4-2.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-client-krb5-1.3.4-2.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-server-krb5-1.3.4-2.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"krb5-", release:"MDK10.0")
 || rpm_exists(rpm:"krb5-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-0468", value:TRUE);
 set_kb_item(name:"CVE-2005-0469", value:TRUE);
}
