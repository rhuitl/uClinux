#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22344);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-4330", "CVE-2006-4331", "CVE-2006-4333");

 name["english"] = "RHSA-2006-0658: wireshark";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  New Wireshark packages that fix various security vulnerabilities are now
  available. Wireshark was previously known as Ethereal.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  Wireshark is a program for monitoring network traffic.

  Bugs were found in Wireshark\'s SCSI and SSCOP protocol dissectors. Ethereal
  could crash or stop responding if it read a malformed packet off the
  network. (CVE-2006-4330, CVE-2006-4333)

  An off-by-one bug was found in the IPsec ESP decryption preference parser.
  Ethereal could crash or stop responding if it read a malformed packet off
  the network. (CVE-2006-4331)

  Users of Wireshark or Ethereal should upgrade to these updated packages
  containing Wireshark version 0.99.3, which is not vulnerable to these
  issues. These packages also fix a bug in the PAM configuration of the
  Wireshark packages which prevented non-root users starting a capture.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0658.html
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
if ( rpm_check( reference:"wireshark-0.99.3-AS21.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wireshark-gnome-0.99.3-AS21.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wireshark-0.99.3-EL3.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wireshark-gnome-0.99.3-EL3.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wireshark-0.99.3-EL4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wireshark-gnome-0.99.3-EL4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"wireshark-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2006-4330", value:TRUE);
 set_kb_item(name:"CVE-2006-4331", value:TRUE);
 set_kb_item(name:"CVE-2006-4333", value:TRUE);
}
if ( rpm_exists(rpm:"wireshark-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-4330", value:TRUE);
 set_kb_item(name:"CVE-2006-4331", value:TRUE);
 set_kb_item(name:"CVE-2006-4333", value:TRUE);
}
if ( rpm_exists(rpm:"wireshark-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-4330", value:TRUE);
 set_kb_item(name:"CVE-2006-4331", value:TRUE);
 set_kb_item(name:"CVE-2006-4333", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0658", value:TRUE);
