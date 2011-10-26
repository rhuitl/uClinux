#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18110);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0755");

 name["english"] = "RHSA-2005-392: HelixPlayer";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated HelixPlayer package that fixes a buffer overflow issue is now
  available.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  HelixPlayer is a media player.

  A buffer overflow bug was found in the way HelixPlayer processes RAM files.
  An attacker could create a specially crafted RAM file which could execute
  arbitrary code when opened by a user. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2005-0755 to
  this issue.

  All users of HelixPlayer are advised to upgrade to this updated package,
  which contains HelixPlayer version 10.0.4 and is not vulnerable to this
  issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-392.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the HelixPlayer packages";
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
if ( rpm_check( reference:"HelixPlayer-1.0.4-1.1.EL4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"HelixPlayer-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0755", value:TRUE);
}

set_kb_item(name:"RHSA-2005-392", value:TRUE);
