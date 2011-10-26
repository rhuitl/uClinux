#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:209
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20442);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2355", "CVE-2005-3088");
 
 name["english"] = "MDKSA-2005:209: fetchmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:209 (fetchmail).



Thomas Wolff and Miloslav Trmac discovered a race condition in the
fetchmailconf program. fetchmailconf would create the initial output
configuration file with insecure permissions and only after writing would it
change permissions to be more restrictive. During that time, passwords and
other data could be exposed to other users on the system unless the user used a
more restrictive umask setting. As well, the Mandriva Linux 2006 packages did
not contain the patch that corrected the issues fixed in MDKSA-2005:126, namely
a buffer overflow in fetchmail's POP3 client (CVE-2005-2355). The updated
packages have been patched to address this issue, and the Mandriva 2006
packages have also been patched to correct CVE-2005-2355.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:209
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the fetchmail package";
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
if ( rpm_check( reference:"fetchmail-6.2.5-5.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-6.2.5-5.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-6.2.5-5.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-6.2.5-10.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-6.2.5-10.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-6.2.5-10.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-6.2.5-11.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-6.2.5-11.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-6.2.5-11.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"fetchmail-", release:"MDK10.1")
 || rpm_exists(rpm:"fetchmail-", release:"MDK10.2")
 || rpm_exists(rpm:"fetchmail-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-2355", value:TRUE);
 set_kb_item(name:"CVE-2005-3088", value:TRUE);
}
