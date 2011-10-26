#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18594);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1993");

 name["english"] = "RHSA-2005-535: sudo";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated sudo package is available that fixes a race condition in sudo\'s
  pathname validation.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The sudo (superuser do) utility allows system administrators to give
  certain users the ability to run commands as root with logging.

  A race condition bug was found in the way sudo handles pathnames. It is
  possible that a local user with limited sudo access could create
  a race condition that would allow the execution of arbitrary commands as
  the root user. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2005-1993 to this issue.

  Users of sudo should update to this updated package, which contains a
  backported patch and is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-535.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sudo packages";
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
if ( rpm_check( reference:"sudo-1.6.5p2-1.7x.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sudo-1.6.7p5-1.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sudo-1.6.7p5-30.1.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"sudo-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-1993", value:TRUE);
}
if ( rpm_exists(rpm:"sudo-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-1993", value:TRUE);
}
if ( rpm_exists(rpm:"sudo-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-1993", value:TRUE);
}

set_kb_item(name:"RHSA-2005-535", value:TRUE);
