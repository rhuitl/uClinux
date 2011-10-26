#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19424);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2360", "CVE-2005-2361", "CVE-2005-2362", "CVE-2005-2363", "CVE-2005-2364", "CVE-2005-2365", "CVE-2005-2366", "CVE-2005-2367");

 name["english"] = "RHSA-2005-687: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Ethereal packages that fix various security vulnerabilities are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The ethereal package is a program for monitoring network traffic.

  A number of security flaws have been discovered in Ethereal. On a system
  where Ethereal is running, a remote attacker could send malicious packets
  to trigger these flaws and cause Ethereal to crash or potentially execute
  arbitrary code. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the names CVE-2005-2360, CVE-2005-2361,
  CVE-2005-2362, CVE-2005-2363, CVE-2005-2364, CVE-2005-2365, CVE-2005-2366,
  and CVE-2005-2367 to these issues.

  Users of ethereal should upgrade to these updated packages, which contain
  version 0.10.12 which is not vulnerable to these issues.

  Note: To reduce the risk of future vulnerabilities in Ethereal, the
  ethereal and tethereal programs in this update have been compiled as
  Position Independant Executables (PIE) for Red Hat Enterprise Linux 3 and
  4. In addition FORTIFY_SOURCE has been enabled for Red Hat Enterprise
  Linux 4 packages to provide compile time and runtime buffer checks.




Solution : http://rhn.redhat.com/errata/RHSA-2005-687.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal packages";
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
if ( rpm_check( reference:"ethereal-0.10.12-1.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.12-1.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.12-1.EL3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.12-1.EL3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.12-1.EL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.12-1.EL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ethereal-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-2360", value:TRUE);
 set_kb_item(name:"CVE-2005-2361", value:TRUE);
 set_kb_item(name:"CVE-2005-2362", value:TRUE);
 set_kb_item(name:"CVE-2005-2363", value:TRUE);
 set_kb_item(name:"CVE-2005-2364", value:TRUE);
 set_kb_item(name:"CVE-2005-2365", value:TRUE);
 set_kb_item(name:"CVE-2005-2366", value:TRUE);
 set_kb_item(name:"CVE-2005-2367", value:TRUE);
}
if ( rpm_exists(rpm:"ethereal-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-2360", value:TRUE);
 set_kb_item(name:"CVE-2005-2361", value:TRUE);
 set_kb_item(name:"CVE-2005-2362", value:TRUE);
 set_kb_item(name:"CVE-2005-2363", value:TRUE);
 set_kb_item(name:"CVE-2005-2364", value:TRUE);
 set_kb_item(name:"CVE-2005-2365", value:TRUE);
 set_kb_item(name:"CVE-2005-2366", value:TRUE);
 set_kb_item(name:"CVE-2005-2367", value:TRUE);
}
if ( rpm_exists(rpm:"ethereal-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2360", value:TRUE);
 set_kb_item(name:"CVE-2005-2361", value:TRUE);
 set_kb_item(name:"CVE-2005-2362", value:TRUE);
 set_kb_item(name:"CVE-2005-2363", value:TRUE);
 set_kb_item(name:"CVE-2005-2364", value:TRUE);
 set_kb_item(name:"CVE-2005-2365", value:TRUE);
 set_kb_item(name:"CVE-2005-2366", value:TRUE);
 set_kb_item(name:"CVE-2005-2367", value:TRUE);
}

set_kb_item(name:"RHSA-2005-687", value:TRUE);
