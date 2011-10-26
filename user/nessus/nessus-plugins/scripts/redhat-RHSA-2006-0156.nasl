#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20480);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3313", "CVE-2005-3651", "CVE-2005-4585");

 name["english"] = "RHSA-2006-0156: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Ethereal packages that fix various security vulnerabilities are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Ethereal is a program for monitoring network traffic.

  Two denial of service bugs were found in Ethereal\'s IRC and GTP protocol
  dissectors. Ethereal could crash or stop responding if it reads a malformed
  IRC or GTP packet off the network. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) assigned the names CVE-2005-3313 and CVE-2005-4585
  to these issues.

  A buffer overflow bug was found in Ethereal\'s OSPF protocol dissector.
  Ethereal could crash or execute arbitrary code if it reads a malformed OSPF
  packet off the network. (CVE-2005-3651)

  Users of ethereal should upgrade to these updated packages containing
  version 0.10.14, which is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0156.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ethereal-0.10.14-1.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.14-1.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.14-1.EL3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.14-1.EL3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.14-1.EL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.14-1.EL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ethereal-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-3313", value:TRUE);
 set_kb_item(name:"CVE-2005-3651", value:TRUE);
 set_kb_item(name:"CVE-2005-4585", value:TRUE);
}
if ( rpm_exists(rpm:"ethereal-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-3313", value:TRUE);
 set_kb_item(name:"CVE-2005-3651", value:TRUE);
 set_kb_item(name:"CVE-2005-4585", value:TRUE);
}
if ( rpm_exists(rpm:"ethereal-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-3313", value:TRUE);
 set_kb_item(name:"CVE-2005-3651", value:TRUE);
 set_kb_item(name:"CVE-2005-4585", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0156", value:TRUE);
