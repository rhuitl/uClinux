#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:103
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21718);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-2447");
 
 name["english"] = "MDKSA-2006:103: spamassassin";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:103 (spamassassin).



A flaw was discovered in the way that spamd processes the virtual POP

usernames passed to it. If running with the --vpopmail and --paranoid

flags, it is possible for a remote user with the ability to connect to

the spamd daemon to execute arbitrary commands as the user running

spamd.



By default, the Spamassassin packages do not start spamd with either

of these flags and this usage is uncommon.



The updated packages have been patched to correct this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:103
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the spamassassin package";
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
if ( rpm_check( reference:"perl-Mail-SpamAssassin-3.0.4-0.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-3.0.4-0.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-spamc-3.0.4-0.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-spamd-3.0.4-0.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-tools-3.0.4-0.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-Mail-SpamAssassin-3.0.4-3.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-3.0.4-3.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-spamc-3.0.4-3.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-spamd-3.0.4-3.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-tools-3.0.4-3.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"spamassassin-", release:"MDK10.2")
 || rpm_exists(rpm:"spamassassin-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-2447", value:TRUE);
}
