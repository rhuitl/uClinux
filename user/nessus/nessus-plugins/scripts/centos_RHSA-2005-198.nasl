#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2005-198.

See also :

https://rhn.redhat.com/errata/RHSA-2005-198.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(21921);
 script_version("$Revision: 1.3 $");
 script_name(english:"CentOS : RHSA-2005-198");
 script_description(english:desc);

 script_summary(english:"Checks for missing updates on the remote CentOS system");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2006 Tenable Network Security, Inc.");
 script_family(english:"CentOS Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/CentOS/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check(reference:"fonts-xorg-100dpi-6.8.1.1-1.EL.1", release:"CentOS-4") )  faulty += '- fonts-xorg-100dpi-6.8.1.1-1.EL.1\n';
if ( rpm_check(reference:"fonts-xorg-75dpi-6.8.1.1-1.EL.1", release:"CentOS-4") )  faulty += '- fonts-xorg-75dpi-6.8.1.1-1.EL.1\n';
if ( rpm_check(reference:"fonts-xorg-base-6.8.1.1-1.EL.1", release:"CentOS-4") )  faulty += '- fonts-xorg-base-6.8.1.1-1.EL.1\n';
if ( rpm_check(reference:"fonts-xorg-cyrillic-6.8.1.1-1.EL.1", release:"CentOS-4") )  faulty += '- fonts-xorg-cyrillic-6.8.1.1-1.EL.1\n';
if ( rpm_check(reference:"fonts-xorg-ISO8859-14-100dpi-6.8.1.1-1.EL.1", release:"CentOS-4") )  faulty += '- fonts-xorg-ISO8859-14-100dpi-6.8.1.1-1.EL.1\n';
if ( rpm_check(reference:"fonts-xorg-ISO8859-14-75dpi-6.8.1.1-1.EL.1", release:"CentOS-4") )  faulty += '- fonts-xorg-ISO8859-14-75dpi-6.8.1.1-1.EL.1\n';
if ( rpm_check(reference:"fonts-xorg-ISO8859-15-100dpi-6.8.1.1-1.EL.1", release:"CentOS-4") )  faulty += '- fonts-xorg-ISO8859-15-100dpi-6.8.1.1-1.EL.1\n';
if ( rpm_check(reference:"fonts-xorg-ISO8859-15-75dpi-6.8.1.1-1.EL.1", release:"CentOS-4") )  faulty += '- fonts-xorg-ISO8859-15-75dpi-6.8.1.1-1.EL.1\n';
if ( rpm_check(reference:"fonts-xorg-ISO8859-2-100dpi-6.8.1.1-1.EL.1", release:"CentOS-4") )  faulty += '- fonts-xorg-ISO8859-2-100dpi-6.8.1.1-1.EL.1\n';
if ( rpm_check(reference:"fonts-xorg-ISO8859-2-75dpi-6.8.1.1-1.EL.1", release:"CentOS-4") )  faulty += '- fonts-xorg-ISO8859-2-75dpi-6.8.1.1-1.EL.1\n';
if ( rpm_check(reference:"fonts-xorg-ISO8859-9-100dpi-6.8.1.1-1.EL.1", release:"CentOS-4") )  faulty += '- fonts-xorg-ISO8859-9-100dpi-6.8.1.1-1.EL.1\n';
if ( rpm_check(reference:"fonts-xorg-ISO8859-9-75dpi-6.8.1.1-1.EL.1", release:"CentOS-4") )  faulty += '- fonts-xorg-ISO8859-9-75dpi-6.8.1.1-1.EL.1\n';
if ( rpm_check(reference:"fonts-xorg-syriac-6.8.1.1-1.EL.1", release:"CentOS-4") )  faulty += '- fonts-xorg-syriac-6.8.1.1-1.EL.1\n';
if ( rpm_check(reference:"fonts-xorg-truetype-6.8.1.1-1.EL.1", release:"CentOS-4") )  faulty += '- fonts-xorg-truetype-6.8.1.1-1.EL.1\n';
if ( rpm_check(reference:"kdbg-1.2.1-7", release:"CentOS-4", cpu:"i386") )  faulty += '- kdbg-1.2.1-7\n';
if ( rpm_check(reference:"ImageMagick-5.3.8-11.c2.1", release:"CentOS-4", cpu:"i386") )  faulty += '- ImageMagick-5.3.8-11.c2.1\n';
if ( rpm_check(reference:"ImageMagick-c++-5.3.8-11.c2.1", release:"CentOS-4", cpu:"i386") )  faulty += '- ImageMagick-c++-5.3.8-11.c2.1\n';
if ( rpm_check(reference:"ImageMagick-c++-devel-5.3.8-11.c2.1", release:"CentOS-4", cpu:"i386") )  faulty += '- ImageMagick-c++-devel-5.3.8-11.c2.1\n';
if ( rpm_check(reference:"ImageMagick-devel-5.3.8-11.c2.1", release:"CentOS-4", cpu:"i386") )  faulty += '- ImageMagick-devel-5.3.8-11.c2.1\n';
if ( rpm_check(reference:"ImageMagick-perl-5.3.8-11.c2.1", release:"CentOS-4", cpu:"i386") )  faulty += '- ImageMagick-perl-5.3.8-11.c2.1\n';
if ( rpm_check(reference:"openssh-3.1p1-18", release:"CentOS-4", cpu:"i386") )  faulty += '- openssh-3.1p1-18\n';
if ( rpm_check(reference:"openssh-askpass-3.1p1-18", release:"CentOS-4", cpu:"i386") )  faulty += '- openssh-askpass-3.1p1-18\n';
if ( rpm_check(reference:"openssh-askpass-gnome-3.1p1-18", release:"CentOS-4", cpu:"i386") )  faulty += '- openssh-askpass-gnome-3.1p1-18\n';
if ( rpm_check(reference:"openssh-clients-3.1p1-18", release:"CentOS-4", cpu:"i386") )  faulty += '- openssh-clients-3.1p1-18\n';
if ( rpm_check(reference:"openssh-server-3.1p1-18", release:"CentOS-4", cpu:"i386") )  faulty += '- openssh-server-3.1p1-18\n';
if ( rpm_check(reference:"xorg-x11-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-Mesa-libGL-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-Mesa-libGL-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-Mesa-libGLU-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-Mesa-libGLU-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-Xdmx-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-Xdmx-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-Xnest-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-Xnest-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-Xvfb-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-Xvfb-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-deprecated-libs-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-deprecated-libs-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-deprecated-libs-devel-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-deprecated-libs-devel-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-devel-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-devel-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-doc-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-doc-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-font-utils-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-font-utils-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-libs-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-libs-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-sdk-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-sdk-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-tools-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-tools-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-twm-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-twm-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-xauth-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-xauth-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-xdm-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-xdm-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-xfs-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-xfs-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-deprecated-libs-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-deprecated-libs-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-deprecated-libs-devel-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-deprecated-libs-devel-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-devel-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-devel-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-doc-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-doc-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-font-utils-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-font-utils-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-libs-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-libs-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-Mesa-libGL-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-Mesa-libGL-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-Mesa-libGLU-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-Mesa-libGLU-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-sdk-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-sdk-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-tools-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-tools-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-twm-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-twm-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-xauth-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-xauth-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-xdm-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-xdm-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-Xdmx-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-Xdmx-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-xfs-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-xfs-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-Xnest-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-Xnest-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-Xvfb-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-Xvfb-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-deprecated-libs-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-deprecated-libs-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-deprecated-libs-devel-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-deprecated-libs-devel-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-devel-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-devel-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-doc-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-doc-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-font-utils-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-font-utils-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-libs-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-libs-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-Mesa-libGL-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-Mesa-libGL-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-Mesa-libGLU-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-Mesa-libGLU-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-sdk-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-sdk-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-tools-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-tools-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-twm-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-twm-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-xauth-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-xauth-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-xdm-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-xdm-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-Xdmx-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-Xdmx-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-xfs-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-xfs-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-Xnest-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-Xnest-6.8.2-1.EL.13.6\n';
if ( rpm_check(reference:"xorg-x11-Xvfb-6.8.2-1.EL.13.6", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-Xvfb-6.8.2-1.EL.13.6\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
