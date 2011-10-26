#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17310);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0208", "CVE-2005-0472", "CVE-2005-0473");

 name["english"] = "RHSA-2005-215: gaim";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated gaim package that fixes various security issues as well as a
  number of bugs is now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Gaim application is a multi-protocol instant messaging client.

  Two HTML parsing bugs were discovered in Gaim. It is possible that a remote
  attacker could send a specially crafted message to a Gaim client, causing
  it to crash. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the names CVE-2005-0208 and CVE-2005-0473 to
  these issues.

  A bug in the way Gaim processes SNAC packets was discovered. It is
  possible that a remote attacker could send a specially crafted SNAC packet
  to a Gaim client, causing the client to stop responding. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-0472 to this issue.

  Additionally, various client crashes, memory leaks, and protocol issues
  have been resolved.

  Users of Gaim are advised to upgrade to this updated package which contains
  Gaim version 1.1.4 and is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-215.html
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
if ( rpm_check( reference:"gaim-1.1.4-1.EL3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-1.1.4-1.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gaim-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0208", value:TRUE);
 set_kb_item(name:"CVE-2005-0472", value:TRUE);
 set_kb_item(name:"CVE-2005-0473", value:TRUE);
}
if ( rpm_exists(rpm:"gaim-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0208", value:TRUE);
 set_kb_item(name:"CVE-2005-0472", value:TRUE);
 set_kb_item(name:"CVE-2005-0473", value:TRUE);
}

set_kb_item(name:"RHSA-2005-215", value:TRUE);
