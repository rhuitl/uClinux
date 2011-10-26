#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16019);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0914");

 name["english"] = "RHSA-2004-612: XFree";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated XFree86 packages that fix several security flaws in libXpm are now
  available for Red Hat Enterprise Linux 3.

  XFree86 is an open source implementation of the X Window System. It
  provides the basic low level functionality which full fledged graphical
  user interfaces (GUIs) such as GNOME and KDE are designed upon.

  Several integer overflow flaws in the X.Org libXpm library used to decode
  XPM (X PixMap) images have been found and addressed. An attacker could
  create a carefully crafted XPM file which would cause an application to
  crash or potentially execute arbitrary code if opened by a victim. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2004-0914 to this issue.

  Users are advised to upgrade to these erratum packages, which contain
  backported security patches as well as other bug fixes.




Solution : http://rhn.redhat.com/errata/RHSA-2004-612.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the XFree packages";
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
if ( rpm_check( reference:"XFree86-100dpi-fonts-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-75dpi-fonts-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-14-100dpi-fonts-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-14-75dpi-fonts-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-15-100dpi-fonts-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-15-75dpi-fonts-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-2-100dpi-fonts-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-2-75dpi-fonts-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-9-100dpi-fonts-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-9-75dpi-fonts-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-Mesa-libGL-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-Mesa-libGLU-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-Xnest-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-Xvfb-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-base-fonts-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-cyrillic-fonts-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-devel-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-doc-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-font-utils-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-libs-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-libs-data-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-sdk-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-syriac-fonts-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-tools-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-truetype-fonts-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-twm-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-xauth-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-xdm-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-xfs-4.3.0-78.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"XFree-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0914", value:TRUE);
}

set_kb_item(name:"RHSA-2004-612", value:TRUE);
