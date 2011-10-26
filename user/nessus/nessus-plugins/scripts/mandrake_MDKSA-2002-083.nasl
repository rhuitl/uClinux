#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:083
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13981);
 script_bugtraq_id(5845);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-1165");
 
 name["english"] = "MDKSA-2002:083: sendmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:083 (sendmail).


A vulnerability was discovered by zen-parse and Pedram Amini in the sendmail
MTA. They found two ways to exploit smrsh, an application intended as a
replacement for the sh shell for use with sendmail; the first by inserting
specially formatted commands in the ~/.forward file and secondly by calling
smrsh directly with special options. These can be exploited to give users with
no shell account, or those not permitted to execute certain programs or
commands, the ability to bypass these restrictions.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:083
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
if ( rpm_check( reference:"sendmail-8.11.0-4.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.11.0-4.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.11.0-4.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.11.6-4.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.11.6-4.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.11.6-4.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.11.6-4.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.11.6-4.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.11.6-4.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.12.1-4.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.12.1-4.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.12.1-4.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.12.1-4.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.12.6-3.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.12.6-3.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.12.6-3.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.12.6-3.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"sendmail-", release:"MDK7.2")
 || rpm_exists(rpm:"sendmail-", release:"MDK8.0")
 || rpm_exists(rpm:"sendmail-", release:"MDK8.1")
 || rpm_exists(rpm:"sendmail-", release:"MDK8.2")
 || rpm_exists(rpm:"sendmail-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-1165", value:TRUE);
}
