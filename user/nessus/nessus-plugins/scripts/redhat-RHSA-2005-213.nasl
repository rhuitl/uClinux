#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17266);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0206");

 name["english"] = "RHSA-2005-213: xpdf";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated xpdf package that correctly fixes several integer overflows is
  now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The xpdf package is an X Window System-based viewer for Portable Document
  Format (PDF) files.

  During a source code audit, Chris Evans and others discovered a number of
  integer overflow bugs that affected all versions of Xpdf. An attacker could
  construct a carefully crafted PDF file that could cause Xpdf to crash or
  possibly execute arbitrary code when opened. This issue was assigned the
  name CVE-2004-0888 by The Common Vulnerabilities and Exposures project
  (cve.mitre.org). RHSA-2004:592 contained a fix for this issue, but it was
  found to be incomplete and left 64-bit architectures vulnerable. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-0206 to this issue.

  All users of xpdf should upgrade to this updated package, which contains
  backported patches to resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-213.html
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
if ( rpm_check( reference:"xpdf-0.92-15", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xpdf-2.02-9.6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"xpdf-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-0206", value:TRUE);
}
if ( rpm_exists(rpm:"xpdf-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0206", value:TRUE);
}

set_kb_item(name:"RHSA-2005-213", value:TRUE);
