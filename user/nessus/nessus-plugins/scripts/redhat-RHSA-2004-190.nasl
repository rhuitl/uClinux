#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12495);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0396");

 name["english"] = "RHSA-2004-190: cvs";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated cvs package that fixes a server vulnerability that could be
  exploited by a malicious client is now available.

  CVS is a version control system frequently used to manage source code
  repositories.

  Stefan Esser discovered a flaw in cvs where malformed "Entry"
  lines could cause a heap overflow. An attacker who has access to a CVS
  server could use this flaw to execute arbitrary code under the UID which
  the CVS server is executing. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CVE-2004-0396 to this issue.

  Users of CVS are advised to upgrade to this updated package, which contains
  a backported patch correcting this issue.

  Red Hat would like to thank Stefan Esser for notifying us of this issue and
  Derek Price for providing an updated patch.




Solution : http://rhn.redhat.com/errata/RHSA-2004-190.html
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
if ( rpm_check( reference:"cvs-1.11.1p1-14", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.2-22", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"cvs-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0396", value:TRUE);
}
if ( rpm_exists(rpm:"cvs-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0396", value:TRUE);
}

set_kb_item(name:"RHSA-2004-190", value:TRUE);
