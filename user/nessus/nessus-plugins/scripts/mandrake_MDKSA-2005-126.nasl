#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:126
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19887);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2335");
 
 name["english"] = "MDKSA-2005:126: fetchmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:126 (fetchmail).



A buffer overflow was discovered in fetchmail's POP3 client which could allow a
malicious server to send a carefully crafted message UID, causing fetchmail to
crash or potentially execute arbitrary code as the user running fetchmail.

The updated packages have been patched to address this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:126
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the fetchmail package";
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
if ( rpm_check( reference:"fetchmail-6.2.5-5.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-6.2.5-5.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-6.2.5-5.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-6.2.5-10.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-6.2.5-10.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-6.2.5-10.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"fetchmail-", release:"MDK10.1")
 || rpm_exists(rpm:"fetchmail-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2335", value:TRUE);
}
