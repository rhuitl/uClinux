#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18554);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1266");

 name["english"] = "RHSA-2005-498: spamassassin";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated spamassassin package that fixes a denial of service bug when
  parsing malformed messages is now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  SpamAssassin provides a way to reduce unsolicited commercial email (SPAM)
  from incoming email.

  A denial of service bug has been found in SpamAssassin. An attacker could
  construct a message in such a way that would cause SpamAssassin to consume
  CPU resources. If a number of these messages were sent it could lead to a
  denial of service, potentially preventing the delivery or filtering of
  email. The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2005-1266 to this issue.

  SpamAssassin version 3.0.4 additionally solves a number of bugs including:
  - #156390 Spamassassin consumes too much memory during learning
  - #155423 URI blacklist spam bypass
  - #147464 Users may now disable subject rewriting
  - Smarter default Bayes scores
  - Numerous other bug fixes that improve spam filter accuracy and safety

  For full details, please refer to the change details of 3.0.2, 3.0.3, and
  3.0.4 in SpamAssassin\'s online documentation at the following address:
  http://wiki.apache.org/spamassassin/NextRelease

  Users of SpamAssassin should update to this updated package, containing
  version 3.0.4 which is not vulnerable to this issue and resolves these
  bugs.




Solution : http://rhn.redhat.com/errata/RHSA-2005-498.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the spamassassin packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"spamassassin-3.0.4-1.el4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"spamassassin-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-1266", value:TRUE);
}

set_kb_item(name:"RHSA-2005-498", value:TRUE);
