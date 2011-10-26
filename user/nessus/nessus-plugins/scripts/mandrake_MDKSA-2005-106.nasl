#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:106
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18583);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-1266");
 
 name["english"] = "MDKSA-2005:106: spamassassin";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:106 (spamassassin).



A Denial of Service bug was discovered in SpamAssassin. An attacker could
construct a particular message that would cause SpamAssassin to consume CPU
resources. If a large number of these messages were sent, it could lead to a
DoS. SpamAssassin 3.0.4 was released to correct this vulnerability, as well as
other minor bug fixes, and is provided with this update.

For full details on the changes from previous versions of SpamAssassin to this
current version, please refer to the online documentation at http://
wiki.apache.org/spamassassin/NextRelease.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:106
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the spamassassin package";
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
if ( rpm_check( reference:"perl-Mail-SpamAssassin-3.0.4-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-3.0.4-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-spamc-3.0.4-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-spamd-3.0.4-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-tools-3.0.4-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-Mail-SpamAssassin-3.0.4-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-3.0.4-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-spamc-3.0.4-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-spamd-3.0.4-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-tools-3.0.4-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"spamassassin-", release:"MDK10.1")
 || rpm_exists(rpm:"spamassassin-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1266", value:TRUE);
}
