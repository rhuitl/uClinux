#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22243);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-3627", "CVE-2006-3628", "CVE-2006-3629", "CVE-2006-3630", "CVE-2006-3631", "CVE-2006-3632");

 name["english"] = "RHSA-2006-0602: wireshark";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  New Wireshark packages that fix various security vulnerabilities in
  Ethereal are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Ethereal is a program for monitoring network traffic.

  In May 2006, Ethereal changed its name to Wireshark. This update
  deprecates the Ethereal packages in Red Hat Enterprise Linux 2.1, 3, and 4
  in favor of the supported Wireshark packages.

  Several denial of service bugs were found in Ethereal\'s protocol
  dissectors. It was possible for Ethereal to crash or stop responding if it
  read a malformed packet off the network. (CVE-2006-3627, CVE-2006-3629,
  CVE-2006-3631)

  Several buffer overflow bugs were found in Ethereal\'s ANSI MAP, NCP NMAS,
  and NDPStelnet dissectors. It was possible for Ethereal to crash or execute
  arbitrary code if it read a malformed packet off the network.
  (CVE-2006-3630, CVE-2006-3632)

  Several format string bugs were found in Ethereal\'s Checkpoint FW-1, MQ,
  XML, and NTP dissectors. It was possible for Ethereal to crash or execute
  arbitrary code if it read a malformed packet off the network. (CVE-2006-3628)

  Users of Ethereal should upgrade to these updated packages containing
  Wireshark version 0.99.2, which is not vulnerable to these issues




Solution : http://rhn.redhat.com/errata/RHSA-2006-0602.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the wireshark packages";
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
if ( rpm_check( reference:"wireshark-0.99.2-AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wireshark-gnome-0.99.2-AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wireshark-0.99.2-EL3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wireshark-gnome-0.99.2-EL3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wireshark-0.99.2-EL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wireshark-gnome-0.99.2-EL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"wireshark-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2006-3627", value:TRUE);
 set_kb_item(name:"CVE-2006-3628", value:TRUE);
 set_kb_item(name:"CVE-2006-3629", value:TRUE);
 set_kb_item(name:"CVE-2006-3630", value:TRUE);
 set_kb_item(name:"CVE-2006-3631", value:TRUE);
 set_kb_item(name:"CVE-2006-3632", value:TRUE);
}
if ( rpm_exists(rpm:"wireshark-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-3627", value:TRUE);
 set_kb_item(name:"CVE-2006-3628", value:TRUE);
 set_kb_item(name:"CVE-2006-3629", value:TRUE);
 set_kb_item(name:"CVE-2006-3630", value:TRUE);
 set_kb_item(name:"CVE-2006-3631", value:TRUE);
 set_kb_item(name:"CVE-2006-3632", value:TRUE);
}
if ( rpm_exists(rpm:"wireshark-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-3627", value:TRUE);
 set_kb_item(name:"CVE-2006-3628", value:TRUE);
 set_kb_item(name:"CVE-2006-3629", value:TRUE);
 set_kb_item(name:"CVE-2006-3630", value:TRUE);
 set_kb_item(name:"CVE-2006-3631", value:TRUE);
 set_kb_item(name:"CVE-2006-3632", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0602", value:TRUE);
