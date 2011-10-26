#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20922);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-4601", "CVE-2006-0082");

 name["english"] = "RHSA-2006-0178: ImageMagick";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated ImageMagick packages that fix two security issues are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  ImageMagick(TM) is an image display and manipulation tool for the X Window
  System that can read and write multiple image formats.

  A shell command injection flaw was found in ImageMagick\'s "display"
  command. It is possible to execute arbitrary commands by tricking a user
  into running "display" on a file with a specially crafted name. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) assigned the name
  CVE-2005-4601 to this issue.

  A format string flaw was discovered in the way ImageMagick handles
  filenames. It may be possible to execute arbitrary commands by tricking a
  user into running a carefully crafted ImageMagick command. (CVE-2006-0082)

  Users of ImageMagick should upgrade to these updated packages, which
  contain backported patches and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0178.html
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
if ( rpm_check( reference:"ImageMagick-5.3.8-14", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-5.3.8-14", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-devel-5.3.8-14", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-5.3.8-14", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-perl-5.3.8-14", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-5.5.6-18", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-5.5.6-18", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-devel-5.5.6-18", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-5.5.6-18", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-perl-5.5.6-18", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-6.0.7.1-14", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-6.0.7.1-14", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-devel-6.0.7.1-14", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-6.0.7.1-14", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-perl-6.0.7.1-14", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ImageMagick-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-4601", value:TRUE);
 set_kb_item(name:"CVE-2006-0082", value:TRUE);
}
if ( rpm_exists(rpm:"ImageMagick-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-4601", value:TRUE);
 set_kb_item(name:"CVE-2006-0082", value:TRUE);
}
if ( rpm_exists(rpm:"ImageMagick-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-4601", value:TRUE);
 set_kb_item(name:"CVE-2006-0082", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0178", value:TRUE);
