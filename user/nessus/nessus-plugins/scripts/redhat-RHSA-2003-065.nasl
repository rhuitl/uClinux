#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12369);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2001-1409", "CVE-2002-0164", "CVE-2002-1510", "CVE-2003-0063", "CVE-2003-0071");

 name["english"] = "RHSA-2003-065: XFree";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated XFree86 packages that resolve various security issues and
  additionally provide a number of bug fixes and enhancements are now
  available for Red Hat Enterprise Linux 2.1.

  XFree86 is an implementation of the X Window System, which provides the
  graphical user interface, video drivers, etc. for Linux systems.

  A number of security vulnerabilities have been found and fixed. In
  addition, various other bug fixes, driver updates, and other enhancements
  have been made.

  Users are advised to upgrade to these updated packages, which contain
  XFree86 version 4.1.0 with patches correcting these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2003-065.html
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
if ( rpm_check( reference:"XFree86-100dpi-fonts-4.1.0-49.RHEL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-4.1.0-49.RHEL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-75dpi-fonts-4.1.0-49.RHEL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-cyrillic-fonts-4.1.0-49.RHEL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-devel-4.1.0-49.RHEL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-doc-4.1.0-49.RHEL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-15-100dpi-fonts-4.1.0-49.RHEL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-15-75dpi-fonts-4.1.0-49.RHEL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-2-100dpi-fonts-4.1.0-49.RHEL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-2-75dpi-fonts-4.1.0-49.RHEL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-9-100dpi-fonts-4.1.0-49.RHEL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-9-75dpi-fonts-4.1.0-49.RHEL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-libs-4.1.0-49.RHEL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-tools-4.1.0-49.RHEL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-twm-4.1.0-49.RHEL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-xdm-4.1.0-49.RHEL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-xf86cfg-4.1.0-49.RHEL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-xfs-4.1.0-49.RHEL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-Xnest-4.1.0-49.RHEL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-Xvfb-4.1.0-49.RHEL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"XFree-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2001-1409", value:TRUE);
 set_kb_item(name:"CVE-2002-0164", value:TRUE);
 set_kb_item(name:"CVE-2002-1510", value:TRUE);
 set_kb_item(name:"CVE-2003-0063", value:TRUE);
 set_kb_item(name:"CVE-2003-0071", value:TRUE);
}

set_kb_item(name:"RHSA-2003-065", value:TRUE);
