#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20060);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-3178");

 name["english"] = "RHSA-2005-802: xloadimage";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  A new xloadimage package that fixes bugs in handling malformed tiff and
  pbm/pnm/ppm images, and in handling metacharacters in file names is now
  available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The xloadimage utility displays images in an X Window System window, loads
  images into the root window, or writes images into a file. Xloadimage
  supports many image types (including GIF, TIFF, JPEG, XPM, and XBM).

  A flaw was discovered in xloadimage via which an attacker can construct a
  NIFF image with a very long embedded image title. This image can cause a
  buffer overflow. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2005-3178 to this issue.

  All users of xloadimage should upgrade to this erratum package, which
  contains backported patches to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-802.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xloadimage packages";
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
if ( rpm_check( reference:"xloadimage-4.1-36.RHEL2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xloadimage-4.1-36.RHEL3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xloadimage-4.1-36.RHEL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"xloadimage-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-3178", value:TRUE);
}
if ( rpm_exists(rpm:"xloadimage-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-3178", value:TRUE);
}
if ( rpm_exists(rpm:"xloadimage-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-3178", value:TRUE);
}

set_kb_item(name:"RHSA-2005-802", value:TRUE);
