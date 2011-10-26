#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19674);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2693");

 name["english"] = "RHSA-2005-756: cvs";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated cvs package that fixes a security bug is now available.

  This update has been rated as having low security impact by the
  Red Hat Security Response Team.

  CVS (Concurrent Version System) is a version control system.

  An insecure temporary file usage was found in the cvsbug program. It is
  possible that a local user could leverage this issue to execute arbitrary
  instructions as the user running cvsbug. The Common Vulnerabilities and
  Exposures project assigned the name CVE-2005-2693 to this issue.

  All users of cvs should upgrade to this updated package, which includes a
  patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-756.html
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
if ( rpm_check( reference:"cvs-1.11.1p1-19", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.2-28", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.17-8.RHEL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"cvs-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-2693", value:TRUE);
}
if ( rpm_exists(rpm:"cvs-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-2693", value:TRUE);
}
if ( rpm_exists(rpm:"cvs-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2693", value:TRUE);
}

set_kb_item(name:"RHSA-2005-756", value:TRUE);
