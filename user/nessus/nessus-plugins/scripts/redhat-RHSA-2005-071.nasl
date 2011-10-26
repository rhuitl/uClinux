#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17179);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0005");

 name["english"] = "RHSA-2005-071: ImageMagick";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated ImageMagick packages that fix a security flaw are now available for
  Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red Hat
  Security Response Team.

  ImageMagick is an image display and manipulation tool for the X Window
  System.

  Andrei Nigmatulin discovered a heap based buffer overflow flaw in the
  ImageMagick image handler. An attacker could create a carefully crafted
  Photoshop Document (PSD) image in such a way that it would cause
  ImageMagick to execute arbitrary code when processing the image. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-0005 to this issue.

  Users of ImageMagick should upgrade to these updated packages, which
  contain a backported patch, and are not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-071.html
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
if ( rpm_check( reference:"ImageMagick-6.0.7.1-6", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-6.0.7.1-6", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-devel-6.0.7.1-6", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-6.0.7.1-6", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-perl-6.0.7.1-6", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ImageMagick-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0005", value:TRUE);
}

set_kb_item(name:"RHSA-2005-071", value:TRUE);
