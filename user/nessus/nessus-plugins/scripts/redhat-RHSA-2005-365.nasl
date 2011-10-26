#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18019);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0965", "CVE-2005-0966", "CVE-2005-0967");

 name["english"] = "RHSA-2005-365: gaim";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated gaim package that fixes multiple denial of service issues is now
  available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Gaim application is a multi-protocol instant messaging client.

  A buffer overflow bug was found in the way gaim escapes HTML. It is
  possible that a remote attacker could send a specially crafted message to a
  Gaim client, causing it to crash. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CVE-2005-0965 to this issue.

  A bug was found in several of gaim\'s IRC processing functions. These
  functions fail to properly remove various markup tags within an IRC
  message. It is possible that a remote attacker could send a specially
  crafted message to a Gaim client connected to an IRC server, causing it to
  crash. The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2005-0966 to this issue.

  A bug was found in gaim\'s Jabber message parser. It is possible for a
  remote Jabber user to send a specially crafted message to a Gaim client,
  causing it to crash. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2005-0967 to this issue.

  In addition to these denial of service issues, multiple minor upstream
  bugfixes are included in this update.

  Users of Gaim are advised to upgrade to this updated package which contains
  Gaim version 1.2.1 and is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-365.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gaim packages";
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
if ( rpm_check( reference:"gaim-1.2.1-4.el3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-1.2.1-4.el4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gaim-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0965", value:TRUE);
 set_kb_item(name:"CVE-2005-0966", value:TRUE);
 set_kb_item(name:"CVE-2005-0967", value:TRUE);
}
if ( rpm_exists(rpm:"gaim-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0965", value:TRUE);
 set_kb_item(name:"CVE-2005-0966", value:TRUE);
 set_kb_item(name:"CVE-2005-0967", value:TRUE);
}

set_kb_item(name:"RHSA-2005-365", value:TRUE);
