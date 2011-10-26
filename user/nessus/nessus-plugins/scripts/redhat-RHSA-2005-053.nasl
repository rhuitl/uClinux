#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17174);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1125", "CVE-2004-1267", "CVE-2004-1268", "CVE-2004-1269", "CVE-2004-1270", "CVE-2005-0064", "CVE-2005-0206");

 name["english"] = "RHSA-2005-053: cups";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated CUPS packages that fix several security issues are now available.

  This update has been rated as having important security impact by the Red
  Hat
  Security Response Team.

  The Common UNIX Printing System provides a portable printing layer for
  UNIX(R) operating systems.

  During a source code audit, Chris Evans and others discovered a number of
  integer overflow bugs that affected all versions of Xpdf, which also
  affects CUPS due to a shared codebase. An attacker could construct a
  carefully crafted PDF file that could cause CUPS to crash or possibly
  execute arbitrary code when opened. This issue was assigned the name
  CVE-2004-0888 by The Common Vulnerabilities and Exposures project
  (cve.mitre.org). Red Hat Enterprise Linux 4 contained a fix for this issue,
  but it was found to be incomplete and left 64-bit architectures vulnerable.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2005-0206 to this issue.

  A buffer overflow flaw was found in the Gfx::doImage function of Xpdf which
  also affects the CUPS pdftops filter due to a shared codebase. An attacker
  who has the ability to send a malicious PDF file to a printer could
  possibly execute arbitrary code as the "lp" user. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-1125 to this issue.

  A buffer overflow flaw was found in the ParseCommand function in the
  hpgltops program. An attacker who has the ability to send a malicious HPGL
  file to a printer could possibly execute arbitrary code as the "lp" user.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2004-1267 to this issue.

  A buffer overflow flaw was found in the Decrypt::makeFileKey2 function of
  Xpdf which also affects the CUPS pdftops filter due to a shared codebase.
  An attacker who has the ability to send a malicious PDF file to a printer
  could possibly execute arbitrary code as the "lp" user. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-0064 to this issue.

  The lppasswd utility was found to ignore write errors when modifying the
  CUPS passwd file. A local user who is able to fill the associated file
  system could corrupt the CUPS password file or prevent future uses of
  lppasswd. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the names CVE-2004-1268 and CVE-2004-1269 to these issues.

  The lppasswd utility was found to not verify that the passwd.new file is
  different from STDERR, which could allow local users to control output to
  passwd.new via certain user input that triggers an error message. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2004-1270 to this issue.

  All users of cups should upgrade to these updated packages, which contain
  backported patches to resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-053.html
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
if ( rpm_check( reference:"cups-1.1.22-0.rc1.9.6", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.22-0.rc1.9.6", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.22-0.rc1.9.6", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"cups-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2004-1125", value:TRUE);
 set_kb_item(name:"CVE-2004-1267", value:TRUE);
 set_kb_item(name:"CVE-2004-1268", value:TRUE);
 set_kb_item(name:"CVE-2004-1269", value:TRUE);
 set_kb_item(name:"CVE-2004-1270", value:TRUE);
 set_kb_item(name:"CVE-2005-0064", value:TRUE);
 set_kb_item(name:"CVE-2005-0206", value:TRUE);
}

set_kb_item(name:"RHSA-2005-053", value:TRUE);
