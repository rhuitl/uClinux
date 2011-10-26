#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:076
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13975);
 script_bugtraq_id(6104);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-1271");
 
 name["english"] = "MDKSA-2002:076: perl-MailTools";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:076 (perl-MailTools).


A vulnerability was discovered in Mail::Mailer perl module by the SuSE security
team during an audit. The vulnerability allows remote attackers to execute
arbitrary commands in certain circumstances due to the usage of mailx as the
default mailer, a program that allows commands to be embedded in the mail body.
This module is used by some auto-response programs and spam filters which make
use of Mail::Mailer.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:076
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the perl-MailTools package";
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
if ( rpm_check( reference:"perl-MailTools-1.47-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-MailTools-1.47-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-MailTools-1.47-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-MailTools-1.47-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-MailTools-1.47-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"perl-MailTools-", release:"MDK7.2")
 || rpm_exists(rpm:"perl-MailTools-", release:"MDK8.0")
 || rpm_exists(rpm:"perl-MailTools-", release:"MDK8.1")
 || rpm_exists(rpm:"perl-MailTools-", release:"MDK8.2")
 || rpm_exists(rpm:"perl-MailTools-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-1271", value:TRUE);
}
