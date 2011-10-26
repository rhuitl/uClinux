#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19712);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2495");

 name["english"] = "RHSA-2005-501: XFree";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated XFree86 packages that fix several integer overflows, various bugs,
  and add ATI RN50/ES1000 support are now available for Red Hat Enterprise
  Linux 3.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  XFree86 is an implementation of the X Window System, which provides
  the core functionality for the Linux graphical desktop.

  Several integer overflow bugs were found in the way XFree86 parses pixmap
  images. It is possible for a user to gain elevated privileges by loading a
  specially crafted pixmap image. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CVE-2005-2495 to this issue.

  Additionally this update adds the following new features in this release:
  - Support for ATI RN50/ES1000 chipsets has been added.

  The following bugs were also fixed in this release:
  - A problem with the X server\'s module loading system that led to cache
  incoherency on the Itanium architecture.

  - The X server\'s PCI config space accesses caused contention
  with the kernel if accesses occurred while the kernel lock was held.

  - X font server (xfs) crashed when accessing Type 1 fonts
  via showfont.

  - A problem with the X transport library prevented X applications
  from starting if the hostname started with a digit.

  - An issue where refresh rates were being restricted to 60Hz on
  some Intel i8xx systems

  Users of XFree86 should upgrade to these updated packages, which contain a
  backported patch and are not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-501.html
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
if ( rpm_check( reference:"XFree86-100dpi-fonts-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-75dpi-fonts-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-14-100dpi-fonts-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-14-75dpi-fonts-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-15-100dpi-fonts-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-15-75dpi-fonts-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-2-100dpi-fonts-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-2-75dpi-fonts-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-9-100dpi-fonts-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-9-75dpi-fonts-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-Mesa-libGL-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-Mesa-libGLU-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-Xnest-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-Xvfb-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-base-fonts-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-cyrillic-fonts-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-devel-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-doc-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-font-utils-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-libs-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-libs-data-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-sdk-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-syriac-fonts-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-tools-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-truetype-fonts-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-twm-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-xauth-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-xdm-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-xfs-4.3.0-95.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"XFree-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-2495", value:TRUE);
}

set_kb_item(name:"RHSA-2005-501", value:TRUE);
