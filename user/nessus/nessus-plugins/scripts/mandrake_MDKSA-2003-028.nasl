#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:028
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14012);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-1337");
 
 name["english"] = "MDKSA-2003:028: sendmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:028 (sendmail).


A vulnerability was discovered in sendmail by Mark Dowd of ISS X-Force that
involves mail header manipulation that can result in a remote user gaining root
access to the system running the vulnerable sendmail.
Patches supplied by the sendmail development team have been applied to correct
this issue. MandrakeSoft encourages all users who have chosen to use sendmail
(as opposed to the default MTA, postfix) to upgrade to this version of sendmail
immediately.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:028
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
if ( rpm_check( reference:"sendmail-8.11.0-4.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.11.0-4.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.11.0-4.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.11.6-4.4mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.11.6-4.4mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.11.6-4.4mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.11.6-4.4mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.11.6-4.4mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.11.6-4.4mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.12.1-4.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.12.1-4.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.12.1-4.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.12.1-4.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.12.6-3.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.12.6-3.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.12.6-3.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.12.6-3.2mdk", release:"MDK9.0", yank:"mdk") )
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
 set_kb_item(name:"CVE-2002-1337", value:TRUE);
}
