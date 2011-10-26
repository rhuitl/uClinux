#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18386);
 script_version ("$Revision: 1.2 $");
 #script_cve_id("CVE-2005-1456", "CVE-2005-1457", "CVE-2005-1458", "CVE-2005-1459", "CVE-2005-1460", "CVE-2005-1461", "CVE-2005-1462", "CVE-2005-1463", "CVE-2005-1464", "CVE-2005-1465", "CVE-2005-1466", "CVE-2005-1467", "CVE-2005-1468", "CVE-2005-1469", "CVE-2005-1470");
 script_cve_id("CVE-2005-1467", "CVE-2005-1468", "CVE-2005-1469", "CVE-2005-1470");

 name["english"] = "RHSA-2005-427: ethereal";
 
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
  (cve.mitre.org) has assigned the names CVE-2005-1456, CVE-2005-1457,
  CVE-2005-1458, CVE-2005-1459, CVE-2005-1460, CVE-2005-1461, CVE-2005-1462,
  CVE-2005-1463, CVE-2005-1464, CVE-2005-1465, CVE-2005-1466, CVE-2005-1467,
  CVE-2005-1468, CVE-2005-1469, and CVE-2005-1470 to these issues.

  Users of ethereal should upgrade to these updated packages, which contain
  version 0.10.11 which is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-427.html
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
if ( rpm_check( reference:"ethereal-0.10.11-1.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.11-1.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.11-1.EL3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.11-1.EL3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.11-1.EL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.11-1.EL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ethereal-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-1456", value:TRUE);
 set_kb_item(name:"CVE-2005-1457", value:TRUE);
 set_kb_item(name:"CVE-2005-1458", value:TRUE);
 set_kb_item(name:"CVE-2005-1459", value:TRUE);
 set_kb_item(name:"CVE-2005-1460", value:TRUE);
 set_kb_item(name:"CVE-2005-1461", value:TRUE);
 set_kb_item(name:"CVE-2005-1462", value:TRUE);
 set_kb_item(name:"CVE-2005-1463", value:TRUE);
 set_kb_item(name:"CVE-2005-1464", value:TRUE);
 set_kb_item(name:"CVE-2005-1465", value:TRUE);
 set_kb_item(name:"CVE-2005-1466", value:TRUE);
 set_kb_item(name:"CVE-2005-1467", value:TRUE);
 set_kb_item(name:"CVE-2005-1468", value:TRUE);
 set_kb_item(name:"CVE-2005-1469", value:TRUE);
 set_kb_item(name:"CVE-2005-1470", value:TRUE);
}
if ( rpm_exists(rpm:"ethereal-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-1456", value:TRUE);
 set_kb_item(name:"CVE-2005-1457", value:TRUE);
 set_kb_item(name:"CVE-2005-1458", value:TRUE);
 set_kb_item(name:"CVE-2005-1459", value:TRUE);
 set_kb_item(name:"CVE-2005-1460", value:TRUE);
 set_kb_item(name:"CVE-2005-1461", value:TRUE);
 set_kb_item(name:"CVE-2005-1462", value:TRUE);
 set_kb_item(name:"CVE-2005-1463", value:TRUE);
 set_kb_item(name:"CVE-2005-1464", value:TRUE);
 set_kb_item(name:"CVE-2005-1465", value:TRUE);
 set_kb_item(name:"CVE-2005-1466", value:TRUE);
 set_kb_item(name:"CVE-2005-1467", value:TRUE);
 set_kb_item(name:"CVE-2005-1468", value:TRUE);
 set_kb_item(name:"CVE-2005-1469", value:TRUE);
 set_kb_item(name:"CVE-2005-1470", value:TRUE);
}
if ( rpm_exists(rpm:"ethereal-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-1456", value:TRUE);
 set_kb_item(name:"CVE-2005-1457", value:TRUE);
 set_kb_item(name:"CVE-2005-1458", value:TRUE);
 set_kb_item(name:"CVE-2005-1459", value:TRUE);
 set_kb_item(name:"CVE-2005-1460", value:TRUE);
 set_kb_item(name:"CVE-2005-1461", value:TRUE);
 set_kb_item(name:"CVE-2005-1462", value:TRUE);
 set_kb_item(name:"CVE-2005-1463", value:TRUE);
 set_kb_item(name:"CVE-2005-1464", value:TRUE);
 set_kb_item(name:"CVE-2005-1465", value:TRUE);
 set_kb_item(name:"CVE-2005-1466", value:TRUE);
 set_kb_item(name:"CVE-2005-1467", value:TRUE);
 set_kb_item(name:"CVE-2005-1468", value:TRUE);
 set_kb_item(name:"CVE-2005-1469", value:TRUE);
 set_kb_item(name:"CVE-2005-1470", value:TRUE);
}

set_kb_item(name:"RHSA-2005-427", value:TRUE);
