#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15747);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0914");
 
 name["english"] = "Fedora Core 2 2004-433: xorg-x11";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-433 (xorg-x11).

X.org X11 is an open source implementation of the X Window System. It
provides the basic low level functionality which full fledged
graphical user interfaces (GUIs) such as GNOME and KDE are designed
upon.

Update Information:

Several integer overflow flaws in the X.Org libXpm library used to
decode
XPM (X PixMap) images have been found and addressed. An attacker could
create a carefully crafted XPM file which would cause an application
to
crash or potentially execute arbitrary code if opened by a victim. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned
the name CVE-2004-0914 to this issue.

Users are advised to upgrade to these erratum packages, which contain
backported security patches as well as other bug fixes.


Solution : http://www.fedoranews.org/blog/index.php?p=94
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xorg-x11 package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"xorg-x11-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-devel-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-font-utils-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-xfs-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-twm-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-xdm-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-libs-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-libs-data-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-base-fonts-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-truetype-fonts-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-syriac-fonts-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-75dpi-fonts-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-100dpi-fonts-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-ISO8859-2-75dpi-fonts-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-ISO8859-2-100dpi-fonts-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-ISO8859-9-75dpi-fonts-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-ISO8859-9-100dpi-fonts-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-ISO8859-14-75dpi-fonts-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-ISO8859-14-100dpi-fonts-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-ISO8859-15-75dpi-fonts-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-ISO8859-15-100dpi-fonts-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-cyrillic-fonts-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-doc-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Xnest-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-tools-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-xauth-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Mesa-libGL-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Mesa-libGLU-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Xvfb-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-sdk-6.7.0-10", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"xorg-x11-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0914", value:TRUE);
}
