#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15411);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0796");

 name["english"] = "RHSA-2004-451: spamassassin";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated spamassassin package that fixes a denial of service bug when
  parsing malformed messages is now available.

  SpamAssassin provides a way to reduce unsolicited commercial email (SPAM)
  from incoming email.

  A denial of service bug has been found in SpamAssassin versions below 2.64.
  A malicious attacker could construct a message in such a way that would
  cause spamassassin to stop responding, potentially preventing the delivery
  or filtering of email. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-0796 to this issue.

  Users of SpamAssassin should update to these updated packages which contain
  a backported patch and is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-451.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the spamassassin packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"spamassassin-2.55-3.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"spamassassin-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0796", value:TRUE);
}

set_kb_item(name:"RHSA-2004-451", value:TRUE);
