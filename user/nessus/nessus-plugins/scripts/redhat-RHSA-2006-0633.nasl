#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22292);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-3743", "CVE-2006-3744", "CVE-2006-4144");

 name["english"] = "RHSA-2006-0633: ImageMagick";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated ImageMagick packages that fix several security issues are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  ImageMagick(TM) is an image display and manipulation tool for the X Window
  System that can read and write multiple image formats.

  Tavis Ormandy discovered several integer and buffer overflow flaws in the
  way ImageMagick decodes XCF, SGI, and Sun bitmap graphic files. An attacker
  could execute arbitrary code on a victim\'s machine if they were able to
  trick the victim into opening a specially crafted image file.
  (CVE-2006-3743, CVE-2006-3744, CVE-2006-4144)

  Users of ImageMagick should upgrade to these updated packages, which
  contain backported patches and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0633.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ImageMagick packages";
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
if ( rpm_check( reference:"ImageMagick-5.3.8-16", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-5.3.8-16", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-devel-5.3.8-16", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-5.3.8-16", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-perl-5.3.8-16", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-5.5.6-20", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-5.5.6-20", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-devel-5.5.6-20", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-5.5.6-20", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-perl-5.5.6-20", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-6.0.7.1-16", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-6.0.7.1-16", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-devel-6.0.7.1-16", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-6.0.7.1-16", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-perl-6.0.7.1-16", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ImageMagick-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2006-3743", value:TRUE);
 set_kb_item(name:"CVE-2006-3744", value:TRUE);
 set_kb_item(name:"CVE-2006-4144", value:TRUE);
}
if ( rpm_exists(rpm:"ImageMagick-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-3743", value:TRUE);
 set_kb_item(name:"CVE-2006-3744", value:TRUE);
 set_kb_item(name:"CVE-2006-4144", value:TRUE);
}
if ( rpm_exists(rpm:"ImageMagick-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-3743", value:TRUE);
 set_kb_item(name:"CVE-2006-3744", value:TRUE);
 set_kb_item(name:"CVE-2006-4144", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0633", value:TRUE);
