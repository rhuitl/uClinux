#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17175);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1125", "CVE-2005-0064", "CVE-2005-0206");

 name["english"] = "RHSA-2005-057: gpdf";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated gpdf package that fixes two security issues is now available.

  This update has been rated as having important security impact by the Red
  Hat
  Security Response Team.

  GPdf is a viewer for Portable Document Format (PDF) files for GNOME.

  A buffer overflow flaw was found in the Gfx::doImage function of Xpdf which
  also affects GPdf due to a shared codebase. An attacker could construct a
  carefully crafted PDF file that could cause GPdf to crash or possibly
  execute arbitrary code when opened. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2004-1125 to
  this issue.

  A buffer overflow flaw was found in the Decrypt::makeFileKey2 function of
  Xpdf which also affects GPdf due to a shared codebase. An attacker could
  construct a carefully crafted PDF file that could cause GPdf to crash or
  possibly execute arbitrary code when opened. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2005-0064 to
  this issue.

  During a source code audit, Chris Evans and others discovered a number of
  integer overflow bugs that affected all versions of Xpdf, which also
  affects GPdf due to a shared codebase. An attacker could construct a
  carefully crafted PDF file that could cause GPdf to crash or possibly
  execute arbitrary code when opened. This issue was assigned the name
  CVE-2004-0888 by The Common Vulnerabilities and Exposures project
  (cve.mitre.org). Red Hat Enterprise Linux 4 contained a fix for this issue,
  but it was found to be incomplete and left 64-bit architectures vulnerable.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2005-0206 to this issue.

  Users should update to this erratum package which contains backported
  patches to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-057.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gpdf packages";
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
if ( rpm_check( reference:"gpdf-2.8.2-4.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gpdf-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2004-1125", value:TRUE);
 set_kb_item(name:"CVE-2005-0064", value:TRUE);
 set_kb_item(name:"CVE-2005-0206", value:TRUE);
}

set_kb_item(name:"RHSA-2005-057", value:TRUE);
