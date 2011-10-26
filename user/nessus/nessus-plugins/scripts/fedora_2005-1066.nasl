#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20190);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3351");
 
 name["english"] = "Fedora Core 4 2005-1066: spamassassin";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-1066 (spamassassin).

SpamAssassin provides you with a way to reduce if not completely eliminate
Unsolicited Commercial Email (SPAM) from your incoming email.  It can
be invoked by a MDA such as sendmail or postfix, or can be called from
a procmail script, .forward file, etc.  It uses a genetic-algorithm
evolved scoring system to identify messages which look spammy, then
adds headers to the message so they can be filtered by the user's mail
reading software.  This distribution includes the spamd/spamc components
which create a server that considerably speeds processing of mail.

To enable spamassassin, if you are receiving mail locally, simply add
this line to your ~/.procmailrc:
INCLUDERC=/etc/mail/spamassassin/spamassassin-default.rc

To filter spam for all users, add that line to /etc/procmailrc
(creating if necessary).

Update Information:

Solves CVE-2005-3351 and a few other minor bugs to improve
spam detection accuracy.  You could consider this a release
candidate for 3.0.5.

Also solved is #161785 which ensures that 'service
spamassassin restart' should never fail.


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the spamassassin package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"spamassassin-3.0.4-2.fc4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"spamassassin-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-3351", value:TRUE);
}
