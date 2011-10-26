#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17621);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0005", "CVE-2005-0397", "CVE-2005-0759", "CVE-2005-0760", "CVE-2005-0761", "CVE-2005-0762");

 name["english"] = "RHSA-2005-070: ImageMagick";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated ImageMagick packages that fix a heap based buffer overflow are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  ImageMagick is an image display and manipulation tool for the X Window
  System.

  Andrei Nigmatulin discovered a heap based buffer overflow flaw in the
  ImageMagick image handler. An attacker could create a carefully crafted
  Photoshop Document (PSD) image in such a way that it would cause
  ImageMagick to execute arbitrary code when processing the image. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-0005 to this issue.

  A format string bug was found in the way ImageMagick handles filenames. An
  attacker could execute arbitrary code on a victim\'s machine if they were
  able to trick the victim into opening a file with a specially crafted name.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2005-0397 to this issue.

  A bug was found in the way ImageMagick handles TIFF tags. It is possible
  that a TIFF image file with an invalid tag could cause ImageMagick to
  crash. The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2005-0759 to this issue.

  A bug was found in ImageMagick\'s TIFF decoder. It is possible that a
  specially crafted TIFF image file could cause ImageMagick to crash. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2005-0760 to this issue.

  A bug was found in the way ImageMagick parses PSD files. It is possible
  that a specially crafted PSD file could cause ImageMagick to crash. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2005-0761 to this issue.

  A heap overflow bug was found in ImageMagick\'s SGI parser. It is possible
  that an attacker could execute arbitrary code by tricking a user into
  opening a specially crafted SGI image file. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2005-0762 to
  this issue.

  Users of ImageMagick should upgrade to these updated packages, which
  contain backported patches, and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-070.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ImageMagick packages";
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
if ( rpm_check( reference:"ImageMagick-5.3.8-10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-5.3.8-10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-devel-5.3.8-10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-5.3.8-10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-perl-5.3.8-10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-5.5.6-13", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-5.5.6-13", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-devel-5.5.6-13", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-5.5.6-13", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-perl-5.5.6-13", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ImageMagick-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-0005", value:TRUE);
 set_kb_item(name:"CVE-2005-0397", value:TRUE);
 set_kb_item(name:"CVE-2005-0759", value:TRUE);
 set_kb_item(name:"CVE-2005-0760", value:TRUE);
 set_kb_item(name:"CVE-2005-0761", value:TRUE);
 set_kb_item(name:"CVE-2005-0762", value:TRUE);
}
if ( rpm_exists(rpm:"ImageMagick-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0005", value:TRUE);
 set_kb_item(name:"CVE-2005-0397", value:TRUE);
 set_kb_item(name:"CVE-2005-0759", value:TRUE);
 set_kb_item(name:"CVE-2005-0760", value:TRUE);
 set_kb_item(name:"CVE-2005-0761", value:TRUE);
 set_kb_item(name:"CVE-2005-0762", value:TRUE);
}

set_kb_item(name:"RHSA-2005-070", value:TRUE);
