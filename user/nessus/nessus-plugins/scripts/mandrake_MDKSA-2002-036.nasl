#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:036
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13941);
 script_bugtraq_id(4788);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0146");
 
 name["english"] = "MDKSA-2002:036: fetchmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:036 (fetchmail).


A problem was discovered with versions of fetchmail prior to 5.9.10 that was
triggered by retreiving mail from an IMAP server. The fetchmail client will
allocate an array to store the sizes of the messages it is attempting to
retrieve. This array size is determined by the number of messages the server is
claiming to have, and fetchmail would not check whether or not the number of
messages the server was claiming was too high. This would allow a malicious
server to make the fetchmail process write data outside of the array bounds.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:036
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
if ( rpm_check( reference:"fetchmail-5.9.11-6.3mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-5.9.11-6.3mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-5.9.11-6.3mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-5.9.11-6.3mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-5.9.11-6.3mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-5.9.11-6.3mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-5.9.11-6.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-5.9.11-6.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-5.9.11-6.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-5.9.11-6.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-5.9.11-6.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-5.9.11-6.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-5.9.11-6.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-5.9.11-6.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-5.9.11-6.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"fetchmail-", release:"MDK7.1")
 || rpm_exists(rpm:"fetchmail-", release:"MDK7.2")
 || rpm_exists(rpm:"fetchmail-", release:"MDK8.0")
 || rpm_exists(rpm:"fetchmail-", release:"MDK8.1")
 || rpm_exists(rpm:"fetchmail-", release:"MDK8.2") )
{
 set_kb_item(name:"CVE-2002-0146", value:TRUE);
}
