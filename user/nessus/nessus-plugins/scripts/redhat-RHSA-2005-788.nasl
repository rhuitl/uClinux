#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19836);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2710");

 name["english"] = "RHSA-2005-788: HelixPlayer";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated HelixPlayer package that fixes a string format issue is now
  available.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  HelixPlayer is a media player.

  A format string bug was discovered in the way HelixPlayer processes RealPix
  (.rp) files. It is possible for a malformed RealPix file to execute
  arbitrary code as the user running HelixPlayer. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name CVE-2005-2710
  to this issue.

  All users of HelixPlayer are advised to upgrade to this updated package,
  which contains HelixPlayer version 10.0.6 and is not vulnerable to this
  issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-788.html
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
if ( rpm_check( reference:"HelixPlayer-1.0.6-0.EL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"HelixPlayer-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2710", value:TRUE);
}

set_kb_item(name:"RHSA-2005-788", value:TRUE);
