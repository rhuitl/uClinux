#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:092
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14074);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-b-0005");
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0681", "CVE-2003-0694");
 
 name["english"] = "MDKSA-2003:092: sendmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:092 (sendmail).


A buffer overflow vulnerability was discovered in the address parsing code in
all versions of sendmail prior to 8.12.10 by Michal Zalewski, with a patch to
fix the problem provided by Todd C. Miller. This vulnerability seems to be
remotely exploitable on Linux systems running on the x86 platform; the sendmail
team is unsure of other platforms (CVE-2003-0694).
Another potential buffer overflow was fixed in ruleset parsing which is not
exploitable in the default sendmail configuration. A problem may occur if
non-standard rulesets recipient (2), final (4), or mailer- specific envelope
recipients rulesets are use. This problem was discovered by Timo Sirainen
(CVE-2003-0681).
MandrakeSoft encourages all users who use sendmail to upgrade to the provided
packages which are patched to fix both problems.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:092
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sendmail package";
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
if ( rpm_check( reference:"sendmail-8.12.1-4.5mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.12.1-4.5mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.12.1-4.5mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.12.1-4.5mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.12.6-3.5mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.12.6-3.5mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.12.6-3.5mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.12.6-3.5mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.12.9-1.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.12.9-1.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.12.9-1.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.12.9-1.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"sendmail-", release:"MDK8.2")
 || rpm_exists(rpm:"sendmail-", release:"MDK9.0")
 || rpm_exists(rpm:"sendmail-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0681", value:TRUE);
 set_kb_item(name:"CVE-2003-0694", value:TRUE);
}
