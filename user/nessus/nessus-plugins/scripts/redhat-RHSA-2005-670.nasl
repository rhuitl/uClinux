#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19410);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2097");

 name["english"] = "RHSA-2005-670: xpdf";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated xpdf package that fixes a security issue is now available for
  Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The xpdf package is an X Window System-based viewer for Portable Document
  Format (PDF) files.

  A flaw was discovered in Xpdf in that an attacker could construct a
  carefully crafted PDF file that would cause Xpdf to consume all available
  disk space in /tmp when opened. The Common Vulnerabilities and Exposures
  project assigned the name CVE-2005-2097 to this issue.

  Note this issue does not affect the version of Xpdf in Red Hat Enterprise
  Linux 3 or 2.1.

  Users of xpdf should upgrade to this updated package, which contains a
  backported patch to resolve this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-670.html
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
if ( rpm_check( reference:"xpdf-3.00-11.8", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"xpdf-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2097", value:TRUE);
}

set_kb_item(name:"RHSA-2005-670", value:TRUE);
