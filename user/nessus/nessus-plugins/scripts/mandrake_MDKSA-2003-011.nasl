#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:011
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13996);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-1365");
 
 name["english"] = "MDKSA-2003:011: fetchmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:011 (fetchmail).


A vulnerability was discovered in all versions of fetchmail prior to 6.2.0 that
allows a remote attacker to crash fetchmail and potentially execute arbitrary
code by sending carefully crafted email wihch is then parsed by fetchmail. The
vulnerability has been fixed in these patched packages of fetchmail.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:011
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the fetchmail package";
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
if ( rpm_check( reference:"fetchmail-6.1.0-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-6.1.0-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-6.1.0-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-6.1.0-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-6.1.0-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-6.1.0-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-6.1.0-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-6.1.0-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-6.1.0-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-6.1.0-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-6.1.0-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-6.1.0-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-6.1.0-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-6.1.0-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-6.1.0-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"fetchmail-", release:"MDK7.2")
 || rpm_exists(rpm:"fetchmail-", release:"MDK8.0")
 || rpm_exists(rpm:"fetchmail-", release:"MDK8.1")
 || rpm_exists(rpm:"fetchmail-", release:"MDK8.2")
 || rpm_exists(rpm:"fetchmail-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-1365", value:TRUE);
}
