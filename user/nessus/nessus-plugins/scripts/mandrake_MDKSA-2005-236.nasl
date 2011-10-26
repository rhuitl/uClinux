#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:236
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20467);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-4348");
 
 name["english"] = "MDKSA-2005:236: fetchmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:236 (fetchmail).



Fetchmail before 6.3.1 and before 6.2.5.5, when configured for multidrop mode,
allows remote attackers to cause a DoS (application crash) by sending messages
without headers from upstream mail servers. The updated packages have been
patched to correct this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:236
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
if ( rpm_check( reference:"fetchmail-6.2.5-5.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-6.2.5-5.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-6.2.5-5.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-6.2.5-10.4.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-6.2.5-10.4.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-6.2.5-10.4.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-6.2.5-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-6.2.5-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-6.2.5-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"fetchmail-", release:"MDK10.1")
 || rpm_exists(rpm:"fetchmail-", release:"MDK10.2")
 || rpm_exists(rpm:"fetchmail-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-4348", value:TRUE);
}
