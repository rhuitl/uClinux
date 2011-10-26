#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21032);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3351");

 name["english"] = "RHSA-2006-0129: spamassassin";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated spamassassin package that fixes a denial of service flaw is now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  SpamAssassin provides a way to reduce unsolicited commercial email (SPAM)
  from incoming email.

  A denial of service bug was found in SpamAssassin. An attacker could
  construct a message in such a way that would cause SpamAssassin to crash.
  If a number of these messages are sent, it could lead to a denial of
  service, potentially preventing the delivery or filtering of email. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) assigned the
  name CVE-2005-3351 to this issue.

  The following issues have also been fixed in this update:

  * service spamassassin restart sometimes fails
  * Content Boundary "--" throws off message parser
  * sa-learn: massive memory usage on large messages
  * High memory usage with many newlines
  * service spamassassin messages not translated
  * Numerous other bug fixes that improve spam filter accuracy and safety

  Users of SpamAssassin should upgrade to this updated package containing
  version 3.0.5, which is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0129.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the spamassassin packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"spamassassin-3.0.5-3.el4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"spamassassin-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-3351", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0129", value:TRUE);
