#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17660);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0605");

 name["english"] = "RHSA-2005-331: XFree";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated XFree86 packages that fix a libXpm integer overflow flaw are now
  available.

  This update has been rated as having moderate security impact by the Red Hat
  Security Response Team.

  XFree86 is an open source implementation of the X Window System. It
  provides the basic low-level functionality that full-fledged graphical
  user interfaces (GUIs) such as GNOME and KDE are designed upon.

  An integer overflow flaw was found in libXpm, which is used by some
  applications for loading of XPM images. An attacker could create a
  malicious XPM file that would execute arbitrary code if opened by a victim
  using an application linked to the vulnerable library. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-0605 to this issue.

  The updated XFree86 packages also address the following minor issues:

  - Updated XFree86-4.3.0-keyboard-disable-ioport-access-v3.patch to make
  warning messages less alarmist.

  - Backported XFree86-4.3.0-libX11-stack-overflow.patch from xorg-x11-6.8.1
  packaging to fix stack overflow in libX11, which was discovered by new
  security features of gcc4.

  Users of XFree86 should upgrade to these updated packages, which contain a
  backported patch and are not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-331.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the XFree packages";
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
if ( rpm_check( reference:"XFree86-100dpi-fonts-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-75dpi-fonts-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-14-100dpi-fonts-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-14-75dpi-fonts-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-15-100dpi-fonts-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-15-75dpi-fonts-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-2-100dpi-fonts-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-2-75dpi-fonts-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-9-100dpi-fonts-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-9-75dpi-fonts-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-Mesa-libGL-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-Mesa-libGLU-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-Xnest-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-Xvfb-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-base-fonts-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-cyrillic-fonts-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-devel-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-doc-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-font-utils-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-libs-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-libs-data-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-sdk-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-syriac-fonts-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-tools-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-truetype-fonts-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-twm-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-xauth-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-xdm-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-xfs-4.3.0-81.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"XFree-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0605", value:TRUE);
}

set_kb_item(name:"RHSA-2005-331", value:TRUE);
