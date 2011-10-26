#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21364);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-1932", "CVE-2006-1933", "CVE-2006-1934", "CVE-2006-1935", "CVE-2006-1936", "CVE-2006-1937", "CVE-2006-1938", "CVE-2006-1939", "CVE-2006-1940");

 name["english"] = "RHSA-2006-0420: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Ethereal packages that fix various security vulnerabilities are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Ethereal is a program for monitoring network traffic.

  Several denial of service bugs were found in Ethereal\'s protocol
  dissectors. Ethereal could crash or stop responding if it reads a malformed
  packet off the network. (CVE-2006-1932, CVE-2006-1933, CVE-2006-1937,
  CVE-2006-1938, CVE-2006-1939, CVE-2006-1940)

  Several buffer overflow bugs were found in Ethereal\'s COPS, telnet, and
  ALCAP dissectors as well as Network Instruments file code and
  NetXray/Windows Sniffer file code. Ethereal could crash or execute
  arbitrary code if it reads a malformed packet off the network.
  (CVE-2006-1934, CVE-2006-1935, CVE-2006-1936)

  Users of ethereal should upgrade to these updated packages containing
  version 0.99.0, which is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0420.html
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
if ( rpm_check( reference:"ethereal-0.99.0-AS21.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.99.0-AS21.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.99.0-EL3.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.99.0-EL3.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.99.0-EL4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.99.0-EL4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ethereal-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2006-1932", value:TRUE);
 set_kb_item(name:"CVE-2006-1933", value:TRUE);
 set_kb_item(name:"CVE-2006-1934", value:TRUE);
 set_kb_item(name:"CVE-2006-1935", value:TRUE);
 set_kb_item(name:"CVE-2006-1936", value:TRUE);
 set_kb_item(name:"CVE-2006-1937", value:TRUE);
 set_kb_item(name:"CVE-2006-1938", value:TRUE);
 set_kb_item(name:"CVE-2006-1939", value:TRUE);
 set_kb_item(name:"CVE-2006-1940", value:TRUE);
}
if ( rpm_exists(rpm:"ethereal-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-1932", value:TRUE);
 set_kb_item(name:"CVE-2006-1933", value:TRUE);
 set_kb_item(name:"CVE-2006-1934", value:TRUE);
 set_kb_item(name:"CVE-2006-1935", value:TRUE);
 set_kb_item(name:"CVE-2006-1936", value:TRUE);
 set_kb_item(name:"CVE-2006-1937", value:TRUE);
 set_kb_item(name:"CVE-2006-1938", value:TRUE);
 set_kb_item(name:"CVE-2006-1939", value:TRUE);
 set_kb_item(name:"CVE-2006-1940", value:TRUE);
}
if ( rpm_exists(rpm:"ethereal-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-1932", value:TRUE);
 set_kb_item(name:"CVE-2006-1933", value:TRUE);
 set_kb_item(name:"CVE-2006-1934", value:TRUE);
 set_kb_item(name:"CVE-2006-1935", value:TRUE);
 set_kb_item(name:"CVE-2006-1936", value:TRUE);
 set_kb_item(name:"CVE-2006-1937", value:TRUE);
 set_kb_item(name:"CVE-2006-1938", value:TRUE);
 set_kb_item(name:"CVE-2006-1939", value:TRUE);
 set_kb_item(name:"CVE-2006-1940", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0420", value:TRUE);
