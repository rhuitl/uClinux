#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18130);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0753");

 name["english"] = "RHSA-2005-387: cvs";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated cvs package that fixes security bugs is now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  CVS (Concurrent Version System) is a version control system.

  A buffer overflow bug was found in the way the CVS client processes version
  and author information. If a user can be tricked into connecting to a
  malicious CVS server, an attacker could execute arbitrary code. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-0753 to this issue.

  Additionally, a bug was found in which CVS freed an invalid pointer.
  However, this issue does not appear to be exploitable.

  All users of cvs should upgrade to this updated package, which includes a
  backported patch to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-387.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cvs packages";
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
if ( rpm_check( reference:"cvs-1.11.1p1-18", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.2-27", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.17-7.RHEL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"cvs-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-0753", value:TRUE);
}
if ( rpm_exists(rpm:"cvs-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0753", value:TRUE);
}
if ( rpm_exists(rpm:"cvs-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0753", value:TRUE);
}

set_kb_item(name:"RHSA-2005-387", value:TRUE);
