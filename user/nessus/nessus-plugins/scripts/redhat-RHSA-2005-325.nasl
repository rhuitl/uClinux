#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17625);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0237", "CVE-2005-0365", "CVE-2005-0396");

 name["english"] = "RHSA-2005-325: kdelibs";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kdelibs packages that fix several security issues are now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kdelibs package provides libraries for the K Desktop Environment.

  The International Domain Name (IDN) support in the Konqueror browser
  allowed remote attackers to spoof domain names using punycode encoded
  domain names. Such domain names are decoded in URLs and SSL certificates
  in a way that uses homograph characters from other character sets, which
  facilitates phishing attacks. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CVE-2005-0237 to this issue.

  Sebastian Krahmer discovered a flaw in dcopserver, the KDE Desktop
  Communication Protocol (DCOP) daemon. A local user could use this flaw to
  stall the DCOP authentication process, affecting any local desktop users
  and causing a reduction in their desktop functionality. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-0396 to this issue.

  A flaw in the dcopidlng script was discovered. The dcopidlng script would
  create temporary files with predictable filenames which could allow local
  users to overwrite arbitrary files via a symlink attack. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2005-0365 to this issue.

  Users of KDE should upgrade to these erratum packages which contain
  backported patches to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-325.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdelibs packages";
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
if ( rpm_check( reference:"kdelibs-3.3.1-3.6", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-3.3.1-3.6", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kdelibs-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0237", value:TRUE);
 set_kb_item(name:"CVE-2005-0365", value:TRUE);
 set_kb_item(name:"CVE-2005-0396", value:TRUE);
}

set_kb_item(name:"RHSA-2005-325", value:TRUE);
