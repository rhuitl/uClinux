#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15535);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0827");

 name["english"] = "RHSA-2004-480: ImageMagick";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated ImageMagick packages that fix a BMP loader vulnerability are now
  available.

  ImageMagick(TM) is an image display and manipulation tool for the X Window
  System.

  A heap overflow flaw has been discovered in the ImageMagick image handler.
  An attacker could create a carefully crafted BMP file in such a way that it
  could cause ImageMagick to execute arbitrary code when processing the
  image. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CVE-2004-0827 to this issue.

  Users of ImageMagick should upgrade to this updated package, which contains
  a backported patch, and is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-480.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ImageMagick packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ImageMagick-5.5.6-6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-5.5.6-6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-devel-5.5.6-6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-5.5.6-6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-perl-5.5.6-6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ImageMagick-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0827", value:TRUE);
}

set_kb_item(name:"RHSA-2004-480", value:TRUE);
