#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18387);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1476", "CVE-2005-1477", "CVE-2005-1531", "CVE-2005-1532");

 name["english"] = "RHSA-2005-434: firefox";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated firefox packages that fix various security bugs are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Mozilla Firefox is an open source Web browser.

  Several bugs were found in the way Firefox executes javascript code.
  Javascript executed from a web page should run with a restricted access
  level, preventing dangerous actions. It is possible that a malicious web
  page could execute javascript code with elevated privileges, allowing
  access to protected data and functions. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the names CVE-2005-1476,
  CVE-2005-1477, CVE-2005-1531, and CVE-2005-1532 to these issues.

  Please note that the effects of CVE-2005-1477 are mitigated by the default
  setup, which allows only the Mozilla Update site to attempt installation of
  Firefox extensions. The Mozilla Update site has been modified to prevent
  this attack from working. If other URLs have been manually added to the
  whitelist, it may be possible to execute this attack.

  Users of Firefox are advised to upgrade to this updated package which
  contains Firefox version 1.0.4 which is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-434.html
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
if ( rpm_check( reference:"firefox-1.0.4-1.4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"firefox-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-1476", value:TRUE);
 set_kb_item(name:"CVE-2005-1477", value:TRUE);
 set_kb_item(name:"CVE-2005-1531", value:TRUE);
 set_kb_item(name:"CVE-2005-1532", value:TRUE);
}

set_kb_item(name:"RHSA-2005-434", value:TRUE);
