#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15632);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0888");

 name["english"] = "RHSA-2004-592: xpdf";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated xpdf package that fixes a number of integer overflow security
  flaws is now available.

  Xpdf is an X Window System based viewer for Portable Document Format
  (PDF) files.

  During a source code audit, Chris Evans and others discovered a number
  of integer overflow bugs that affected all versions of xpdf. An
  attacker could construct a carefully crafted PDF file that could cause
  xpdf to crash or possibly execute arbitrary code when opened. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-0888 to this issue.

  Users of xpdf are advised to upgrade to this errata package, which contains
  a backported patch correcting these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-592.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xpdf packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"xpdf-0.92-13", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xpdf-2.02-9.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"xpdf-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0888", value:TRUE);
}
if ( rpm_exists(rpm:"xpdf-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0888", value:TRUE);
}

set_kb_item(name:"RHSA-2004-592", value:TRUE);
