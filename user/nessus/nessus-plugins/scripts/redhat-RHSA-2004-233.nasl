#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12500);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0414", "CVE-2004-0416", "CVE-2004-0417", "CVE-2004-0418", "CVE-2004-0778");

 name["english"] = "RHSA-2004-233: cvs";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated cvs package that fixes several server vulnerabilities, which
  could
  be exploited by a malicious client, is now available.

  CVS is a version control system frequently used to manage source code
  repositories.

  While investigating a previously fixed vulnerability, Derek Price
  discovered a flaw relating to malformed "Entry" lines which lead to a
  missing NULL terminator. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CVE-2004-0414 to this issue.

  Stefan Esser and Sebastian Krahmer conducted an audit of CVS and fixed a
  number of issues that may have had security consequences.

  Among the issues deemed likely to be exploitable were:

  -- a double-free relating to the error_prog_name string (CVE-2004-0416)
  -- an argument integer overflow (CVE-2004-0417)
  -- out-of-bounds writes in serv_notify (CVE-2004-0418).

  An attacker who has access to a CVS server may be able to execute arbitrary
  code under the UID on which the CVS server is executing.

  Users of CVS are advised to upgrade to this updated package, which contains
  backported patches correcting these issues.

  Red Hat would like to thank Stefan Esser, Sebastian Krahmer, and Derek
  Price for auditing, disclosing, and providing patches for these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-233.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cvs packages";
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
if ( rpm_check( reference:"cvs-1.11.1p1-16", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.2-24", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"cvs-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0414", value:TRUE);
 set_kb_item(name:"CVE-2004-0416", value:TRUE);
 set_kb_item(name:"CVE-2004-0417", value:TRUE);
 set_kb_item(name:"CVE-2004-0418", value:TRUE);
 set_kb_item(name:"CVE-2004-0778", value:TRUE);
}
if ( rpm_exists(rpm:"cvs-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0414", value:TRUE);
 set_kb_item(name:"CVE-2004-0416", value:TRUE);
 set_kb_item(name:"CVE-2004-0417", value:TRUE);
 set_kb_item(name:"CVE-2004-0418", value:TRUE);
 set_kb_item(name:"CVE-2004-0778", value:TRUE);
}

set_kb_item(name:"RHSA-2004-233", value:TRUE);
