#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21288);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0292", "CVE-2006-0296", "CVE-2006-0749", "CVE-2006-1045", "CVE-2006-1724", "CVE-2006-1727", "CVE-2006-1728", "CVE-2006-1730", "CVE-2006-1731", "CVE-2006-1732", "CVE-2006-1733", "CVE-2006-1734", "CVE-2006-1735", "CVE-2006-1737", "CVE-2006-1738", "CVE-2006-1739", "CVE-2006-1741", "CVE-2006-1742", "CVE-2006-1790");

 name["english"] = "RHSA-2006-0330: thunderbird";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated thunderbird package that fixes various bugs is now available for
  Red Hat Enterprise Linux 4.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla Thunderbird is a standalone mail and newsgroup client.

  Several bugs were found in the way Thunderbird processes malformed
  javascript. A malicious HTML mail message could modify the content of a
  different open HTML mail message, possibly stealing sensitive information
  or conducting a cross-site scripting attack. Please note that JavaScript
  support is disabled by default in Thunderbird. (CVE-2006-1731,
  CVE-2006-1732, CVE-2006-1741)

  Several bugs were found in the way Thunderbird processes certain
  javascript actions. A malicious HTML mail message could execute arbitrary
  javascript instructions with the permissions of \'chrome\', allowing the
  page to steal sensitive information or install browser malware. Please
  note that JavaScript support is disabled by default in Thunderbird.
  (CVE-2006-0292, CVE-2006-0296, CVE-2006-1727, CVE-2006-1728, CVE-2006-1733,
  CVE-2006-1734, CVE-2006-1735, CVE-2006-1742)

  Several bugs were found in the way Thunderbird processes malformed HTML
  mail messages. A carefully crafted malicious HTML mail message could
  cause the execution of arbitrary code as the user running Thunderbird.
  (CVE-2006-0749, CVE-2006-1724, CVE-2006-1730, CVE-2006-1737, CVE-2006-1738,
  CVE-2006-1739, CVE-2006-1790)

  A bug was found in the way Thunderbird processes certain inline content
  in HTML mail messages. It may be possible for a remote attacker to send a
  carefully crafted mail message to the victim, which will fetch remote
  content, even if Thunderbird is configured not to fetch remote content.
  (CVE-2006-1045)

  Users of Thunderbird are advised to upgrade to this updated package
  containing Thunderbird version 1.0.8, which is not vulnerable to these
  issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0330.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the thunderbird packages";
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
if ( rpm_check( reference:"thunderbird-1.0.8-1.4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"thunderbird-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-0292", value:TRUE);
 set_kb_item(name:"CVE-2006-0296", value:TRUE);
 set_kb_item(name:"CVE-2006-0749", value:TRUE);
 set_kb_item(name:"CVE-2006-1045", value:TRUE);
 set_kb_item(name:"CVE-2006-1724", value:TRUE);
 set_kb_item(name:"CVE-2006-1727", value:TRUE);
 set_kb_item(name:"CVE-2006-1728", value:TRUE);
 set_kb_item(name:"CVE-2006-1730", value:TRUE);
 set_kb_item(name:"CVE-2006-1731", value:TRUE);
 set_kb_item(name:"CVE-2006-1732", value:TRUE);
 set_kb_item(name:"CVE-2006-1733", value:TRUE);
 set_kb_item(name:"CVE-2006-1734", value:TRUE);
 set_kb_item(name:"CVE-2006-1735", value:TRUE);
 set_kb_item(name:"CVE-2006-1737", value:TRUE);
 set_kb_item(name:"CVE-2006-1738", value:TRUE);
 set_kb_item(name:"CVE-2006-1739", value:TRUE);
 set_kb_item(name:"CVE-2006-1741", value:TRUE);
 set_kb_item(name:"CVE-2006-1742", value:TRUE);
 set_kb_item(name:"CVE-2006-1790", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0330", value:TRUE);
