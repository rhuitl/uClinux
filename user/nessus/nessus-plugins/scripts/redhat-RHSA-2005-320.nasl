#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17623);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0397");

 name["english"] = "RHSA-2005-320: ImageMagick";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated ImageMagick packages that fix a format string bug are now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  ImageMagick(TM) is an image display and manipulation tool for the X Window
  System which can read and write multiple image formats.

  A format string bug was found in the way ImageMagick handles filenames. An
  attacker could execute arbitrary code on a victim\'s machine if they were
  able to trick the victim into opening a file with a specially crafted name.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2005-0397 to this issue.

  Additionally, a bug was fixed which caused ImageMagick(TM) to occasionally
  segfault when writing TIFF images to standard output.

  Users of ImageMagick should upgrade to these updated packages, which
  contain a backported patch, and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-320.html
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
if ( rpm_check( reference:"ImageMagick-6.0.7.1-10", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-6.0.7.1-10", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-devel-6.0.7.1-10", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-6.0.7.1-10", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-perl-6.0.7.1-10", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ImageMagick-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0397", value:TRUE);
}

set_kb_item(name:"RHSA-2005-320", value:TRUE);
