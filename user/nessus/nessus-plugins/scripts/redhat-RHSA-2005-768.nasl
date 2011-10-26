#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19676);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2871");

 name["english"] = "RHSA-2005-768: firefox";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated firefox package that fixes as security bug is now available for
  Red Hat Enterprise Linux 4.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla Firefox is an open source Web browser.

  A bug was found in the way Firefox processes certain international domain
  names. An attacker could create a specially crafted HTML file, which when
  viewed by the victim would cause Firefox to crash or possibly execute
  arbitrary code. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2005-2871 to this issue.

  Users of Firefox are advised to upgrade to this updated package that
  contains a backported patch and is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-768.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the firefox packages";
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
if ( rpm_check( reference:"firefox-1.0.6-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"firefox-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2871", value:TRUE);
}

set_kb_item(name:"RHSA-2005-768", value:TRUE);
