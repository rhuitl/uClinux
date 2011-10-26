#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17149);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0206");

 name["english"] = "RHSA-2005-132: cups";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated cups packages that fix a security issue are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Common UNIX Printing System (CUPS) is a print spooler.

  During a source code audit, Chris Evans discovered a number of integer
  overflow bugs that affect Xpdf. CUPS contained a copy of the Xpdf code
  used for parsing PDF files and was therefore affected by these bugs. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) assigned the
  name CVE-2004-0888 to this issue, and Red Hat released erratum
  RHSA-2004:543 with updated packages.

  It was found that the patch used to correct this issue was not sufficient
  and did not fully protect CUPS running on 64-bit architectures. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-0206 to this issue.

  These updated packages also include a fix that prevents the CUPS
  initscript from being accidentally replaced.

  All users of CUPS on 64-bit architectures should upgrade to these updated
  packages, which contain a corrected patch and are not vulnerable to these
  issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-132.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cups packages";
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
if ( rpm_check( reference:"cups-1.1.17-13.3.27", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.17-13.3.27", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.17-13.3.27", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"cups-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0206", value:TRUE);
}

set_kb_item(name:"RHSA-2005-132", value:TRUE);
