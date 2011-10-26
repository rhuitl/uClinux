#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12345);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-1384");

 name["english"] = "RHSA-2002-307: xpdf";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Xpdf packages are available to fix a vulnerability where a
  malicious PDF document could run arbitrary code.

  [Updated 06 Feb 2003]
  Added fixed packages for Advanced Workstation 2.1

  Xpdf is an X Window System based viewer for Portable Document Format
  (PDF) files.

  During an audit of CUPS, a printing system, Zen Parsec found an integer
  overflow vulnerability in the pdftops filter. Since the code for pdftops
  is taken from the Xpdf project, all versions of Xpdf including 2.01 are
  also vulnerable to this issue. An attacker could create a malicious PDF
  file that would execute arbitrary code as the user who used Xpdf to view
  it.

  All users of Xpdf are advised to upgrade to these errata packages which
  contain a patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2002-307.html
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
if ( rpm_check( reference:"xpdf-0.92-8", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"xpdf-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-1384", value:TRUE);
}

set_kb_item(name:"RHSA-2002-307", value:TRUE);
