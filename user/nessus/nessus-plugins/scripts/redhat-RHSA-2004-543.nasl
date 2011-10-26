#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15630);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0888", "CVE-2004-0923");

 name["english"] = "RHSA-2004-543: cups";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated cups packages that fix denial of service issues, a security
  information leak, as well as other various bugs are now available.

  The Common UNIX Printing System (CUPS) is a print spooler.

  During a source code audit, Chris Evans discovered a number of integer
  overflow bugs that affect xpdf. CUPS contains a copy of the xpdf code used
  for parsing PDF files and is therefore affected by these bugs. An attacker
  who has the ability to send a malicious PDF file to a printer could cause
  CUPS to crash or possibly execute arbitrary code. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-0888 to this issue.

  When set up to print to a shared printer via Samba, CUPS would authenticate
  with that shared printer using a username and password. By default, the
  username and password used to connect to the Samba share is written
  into the error log file. A local user who is able to read the error log
  file could collect these usernames and passwords. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-0923 to this issue.

  These updated packages also include a fix that prevents some CUPS
  configuration files from being accidentally replaced.

  All users of CUPS should upgrade to these updated packages, which
  resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-543.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cups packages";
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
if ( rpm_check( reference:"cups-1.1.17-13.3.16", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.17-13.3.16", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.17-13.3.16", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.17-13.3.16", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.17-13.3.16", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"cups-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0888", value:TRUE);
 set_kb_item(name:"CVE-2004-0923", value:TRUE);
}

set_kb_item(name:"RHSA-2004-543", value:TRUE);
