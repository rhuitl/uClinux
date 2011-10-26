#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16146);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1125", "CVE-2004-1267", "CVE-2004-1268", "CVE-2004-1269", "CVE-2004-1270");

 name["english"] = "RHSA-2005-013: cups";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated CUPS packages that fix several security issues are now available.

  The Common UNIX Printing System provides a portable printing layer for
  UNIX(R) operating systems.

  A buffer overflow was found in the CUPS pdftops filter, which uses code
  from the Xpdf package. An attacker who has the ability to send a malicious
  PDF file to a printer could possibly execute arbitrary code as the "lp"
  user. The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2004-1125 to this issue.

  A buffer overflow was found in the ParseCommand function in the hpgltops
  program. An attacker who has the ability to send a malicious HPGL file to a
  printer could possibly execute arbitrary code as the "lp" user. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-1267 to this issue.

  Red Hat believes that the Exec-Shield technology (enabled by default since
  Update 3) will block attempts to exploit these buffer overflow
  vulnerabilities on x86 architectures.

  The lppasswd utility ignores write errors when modifying the CUPS passwd
  file. A local user who is able to fill the associated file system could
  corrupt the CUPS password file or prevent future uses of lppasswd. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the names CVE-2004-1268 and CVE-2004-1269 to these issues.

  The lppasswd utility does not verify that the passwd.new file is different
  from STDERR, which could allow local users to control output to passwd.new
  via certain user input that triggers an error message. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-1270 to this issue.

  In addition to these security issues, two other problems not relating
  to security have been fixed:

  Resuming a job with "lp -H resume", which had previously been held with "lp
  -H hold" could cause the scheduler to stop. This has been fixed in later
  versions of CUPS, and has been backported in these updated packages.

  The cancel-cups(1) man page is a symbolic link to another man page. The
  target of this link has been corrected.

  All users of cups should upgrade to these updated packages, which resolve
  these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-013.html
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
if ( rpm_check( reference:"cups-1.1.17-13.3.22", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.17-13.3.22", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.17-13.3.22", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"cups-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-1125", value:TRUE);
 set_kb_item(name:"CVE-2004-1267", value:TRUE);
 set_kb_item(name:"CVE-2004-1268", value:TRUE);
 set_kb_item(name:"CVE-2004-1269", value:TRUE);
 set_kb_item(name:"CVE-2004-1270", value:TRUE);
}

set_kb_item(name:"RHSA-2005-013", value:TRUE);
