#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19423);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2102", "CVE-2005-2103", "CVE-2005-2370");

 name["english"] = "RHSA-2005-627: gaim";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated gaim package that fixes multiple security issues is now
  available.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Gaim is an Internet Messaging client.

  A heap based buffer overflow issue was discovered in the way Gaim processes
  away messages. A remote attacker could send a specially crafted away
  message to a Gaim user logged into AIM or ICQ that could result in
  arbitrary code execution. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2005-2103 to this issue.

  Daniel Atallah discovered a denial of service issue in Gaim. A remote
  attacker could attempt to upload a file with a specially crafted name to a
  user logged into AIM or ICQ, causing Gaim to crash. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-2102 to this issue.

  A denial of service bug was found in Gaim\'s Gadu Gadu protocol handler. A
  remote attacker could send a specially crafted message to a Gaim user
  logged into Gadu Gadu, causing Gaim to crash. Please note that this issue
  only affects PPC and IBM S/390 systems running Gaim. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-2370 to this issue.

  Users of gaim are advised to upgrade to this updated package, which
  contains backported patches and is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-627.html
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
if ( rpm_check( reference:"gaim-1.3.1-0.el3.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-1.3.1-0.el4.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gaim-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-2102", value:TRUE);
 set_kb_item(name:"CVE-2005-2103", value:TRUE);
 set_kb_item(name:"CVE-2005-2370", value:TRUE);
}
if ( rpm_exists(rpm:"gaim-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2102", value:TRUE);
 set_kb_item(name:"CVE-2005-2103", value:TRUE);
 set_kb_item(name:"CVE-2005-2370", value:TRUE);
}

set_kb_item(name:"RHSA-2005-627", value:TRUE);
