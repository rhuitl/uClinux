#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18241);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0472", "CVE-2005-1261");

 name["english"] = "RHSA-2005-432: gaim";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated gaim package that fixes security issues is now available for Red
  Hat Enterprise Linux 2.1.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  The Gaim application is a multi-protocol instant messaging client.

  A stack based buffer overflow bug was found in the way gaim processes a
  message containing a URL. A remote attacker could send a carefully crafted
  message resulting in the execution of arbitrary code on a victim\'s machine.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2005-1261 to this issue.

  A bug in the way Gaim processes SNAC packets was discovered. It is possible
  that a remote attacker could send a specially crafted SNAC packet to a Gaim
  client, causing the client to stop responding. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name CVE-2005-0472
  to this issue.

  Users of Gaim are advised to upgrade to this updated package which contains
  gaim version 0.59.9 with backported patches to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-432.html
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
if ( rpm_check( reference:"gaim-0.59.9-4.el2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gaim-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-0472", value:TRUE);
 set_kb_item(name:"CVE-2005-1261", value:TRUE);
}

set_kb_item(name:"RHSA-2005-432", value:TRUE);
