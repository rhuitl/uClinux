#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18093);
 script_version ("$Revision: 1.2 $");

 name["english"] = "RHSA-2005-332: xloadimage";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  A new xloadimage package that fixes bugs in handling malformed tiff
  and pbm/pnm/ppm images, and in handling metacharacters in filenames is now
  available.

  This update has been rated as having low security impact by the
  Red Hat Security Response Team.

  The xloadimage utility displays images in an X Window System window,
  loads images into the root window, or writes images into a file.
  Xloadimage supports many image types (including GIF, TIFF, JPEG, XPM,
  and XBM).

  A flaw was discovered in xloadimage where filenames were not properly
  quoted when calling the gunzip command. An attacker could create a file
  with a carefully crafted filename so that it would execute arbitrary
  commands if opened by a victim. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2005-0638 to
  this issue.

  Another bug in xloadimage would cause it to crash if called with certain
  invalid TIFF, PNM, PBM, or PPM file names.

  All users of xloadimage should upgrade to this erratum package which
  contains backported patches to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-332.html
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
if ( rpm_check( reference:"xloadimage-4.1-34.RHEL2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xloadimage-4.1-34.RHEL3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xloadimage-4.1-34.RHEL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}


set_kb_item(name:"RHSA-2005-332", value:TRUE);
