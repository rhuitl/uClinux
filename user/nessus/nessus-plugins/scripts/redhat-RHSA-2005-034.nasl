#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17168);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1125", "CVE-2005-0064", "CVE-2005-0206");

 name["english"] = "RHSA-2005-034: xpdf";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated xpdf package that fixes several security issues is now
  available.

  This update has been rated as having important security impact by the Red
  Hat
  Security Response Team.

  Xpdf is an X Window System based viewer for Portable Document Format (PDF)
  files.

  A buffer overflow flaw was found in the Gfx::doImage function of Xpdf. An
  attacker could construct a carefully crafted PDF file that could cause Xpdf
  to crash or possibly execute arbitrary code when opened. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-1125 to this issue.

  A buffer overflow flaw was found in the Decrypt::makeFileKey2 function of
  Xpdf. An attacker could construct a carefully crafted PDF file that could
  cause Xpdf to crash or possibly execute arbitrary code when opened. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2005-0064 to this issue.

  During a source code audit, Chris Evans and others discovered a number of
  integer overflow bugs that affected all versions of Xpdf. An attacker could
  construct a carefully crafted PDF file that could cause Xpdf to crash or
  possibly execute arbitrary code when opened. This issue was assigned the
  name CVE-2004-0888 by The Common Vulnerabilities and Exposures project
  (cve.mitre.org). Red Hat Enterprise Linux 4 contained a fix for this
  issue, but it was found to be incomplete and left 64-bit architectures
  vulnerable. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2005-0206 to this issue.

  All users of Xpdf should upgrade to this updated package, which contains
  backported patches to resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-034.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xpdf packages";
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
if ( rpm_check( reference:"xpdf-3.00-11.5", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"xpdf-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2004-1125", value:TRUE);
 set_kb_item(name:"CVE-2005-0064", value:TRUE);
 set_kb_item(name:"CVE-2005-0206", value:TRUE);
}

set_kb_item(name:"RHSA-2005-034", value:TRUE);
