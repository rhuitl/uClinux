#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:221
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20452);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3351");
 
 name["english"] = "MDKSA-2005:221: spamassassin";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:221 (spamassassin).



SpamAssassin 3.0.4 allows attackers to bypass spam detection via an e-mail with
a large number of recipients ('To' addresses), which triggers a bus error in
Perl. Updated packages have been patched to address this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:221
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
if ( rpm_check( reference:"perl-Mail-SpamAssassin-3.0.4-0.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-3.0.4-0.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-spamc-3.0.4-0.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-spamd-3.0.4-0.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-tools-3.0.4-0.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-Mail-SpamAssassin-3.0.4-0.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-3.0.4-0.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-spamc-3.0.4-0.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-spamd-3.0.4-0.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-tools-3.0.4-0.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-Mail-SpamAssassin-3.0.4-3.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-3.0.4-3.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-spamc-3.0.4-3.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-spamd-3.0.4-3.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-tools-3.0.4-3.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"spamassassin-", release:"MDK10.1")
 || rpm_exists(rpm:"spamassassin-", release:"MDK10.2")
 || rpm_exists(rpm:"spamassassin-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3351", value:TRUE);
}
