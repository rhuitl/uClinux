#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2006-0635.

See also :

https://rhn.redhat.com/errata/RHSA-2006-0635.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(22258);
 script_version("$Revision: 1.2 $");
 script_name(english:"CentOS : RHSA-2006-0635");
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

if ( rpm_check(reference:"wireshark-0.99.2-AS21.1", release:"CentOS-3", cpu:"i386") )  faulty += '- wireshark-0.99.2-AS21.1\n';
if ( rpm_check(reference:"wireshark-gnome-0.99.2-AS21.1", release:"CentOS-3", cpu:"i386") )  faulty += '- wireshark-gnome-0.99.2-AS21.1\n';
if ( rpm_check(reference:"XFree86-100dpi-fonts-4.1.0-76.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-100dpi-fonts-4.1.0-76.EL\n';
if ( rpm_check(reference:"XFree86-4.1.0-76.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-4.1.0-76.EL\n';
if ( rpm_check(reference:"XFree86-75dpi-fonts-4.1.0-76.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-75dpi-fonts-4.1.0-76.EL\n';
if ( rpm_check(reference:"XFree86-cyrillic-fonts-4.1.0-76.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-cyrillic-fonts-4.1.0-76.EL\n';
if ( rpm_check(reference:"XFree86-devel-4.1.0-76.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-devel-4.1.0-76.EL\n';
if ( rpm_check(reference:"XFree86-doc-4.1.0-76.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-doc-4.1.0-76.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-15-100dpi-fonts-4.1.0-76.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-ISO8859-15-100dpi-fonts-4.1.0-76.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-15-75dpi-fonts-4.1.0-76.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-ISO8859-15-75dpi-fonts-4.1.0-76.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-2-100dpi-fonts-4.1.0-76.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-ISO8859-2-100dpi-fonts-4.1.0-76.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-2-75dpi-fonts-4.1.0-76.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-ISO8859-2-75dpi-fonts-4.1.0-76.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-9-100dpi-fonts-4.1.0-76.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-ISO8859-9-100dpi-fonts-4.1.0-76.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-9-75dpi-fonts-4.1.0-76.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-ISO8859-9-75dpi-fonts-4.1.0-76.EL\n';
if ( rpm_check(reference:"XFree86-libs-4.1.0-76.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-libs-4.1.0-76.EL\n';
if ( rpm_check(reference:"XFree86-tools-4.1.0-76.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-tools-4.1.0-76.EL\n';
if ( rpm_check(reference:"XFree86-twm-4.1.0-76.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-twm-4.1.0-76.EL\n';
if ( rpm_check(reference:"XFree86-xdm-4.1.0-76.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-xdm-4.1.0-76.EL\n';
if ( rpm_check(reference:"XFree86-xf86cfg-4.1.0-76.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-xf86cfg-4.1.0-76.EL\n';
if ( rpm_check(reference:"XFree86-xfs-4.1.0-76.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-xfs-4.1.0-76.EL\n';
if ( rpm_check(reference:"XFree86-Xnest-4.1.0-76.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-Xnest-4.1.0-76.EL\n';
if ( rpm_check(reference:"XFree86-Xvfb-4.1.0-76.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-Xvfb-4.1.0-76.EL\n';
if ( rpm_check(reference:"XFree86-100dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-100dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-75dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-75dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-base-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-base-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-cyrillic-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-cyrillic-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-devel-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-devel-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-doc-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-doc-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-font-utils-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-font-utils-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-14-100dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-ISO8859-14-100dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-14-75dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-ISO8859-14-75dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-15-100dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-ISO8859-15-100dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-15-75dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-ISO8859-15-75dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-2-100dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-ISO8859-2-100dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-2-75dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-ISO8859-2-75dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-9-100dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-ISO8859-9-100dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-9-75dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-ISO8859-9-75dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-libs-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-libs-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-libs-data-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-libs-data-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-Mesa-libGL-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-Mesa-libGL-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-Mesa-libGLU-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-Mesa-libGLU-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-sdk-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-sdk-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-syriac-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-syriac-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-tools-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-tools-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-truetype-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-truetype-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-twm-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-twm-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-xauth-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-xauth-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-xdm-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-xdm-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-xfs-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-xfs-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-Xnest-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-Xnest-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-Xvfb-4.3.0-111.EL", release:"CentOS-3", cpu:"i386") )  faulty += '- XFree86-Xvfb-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-100dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-100dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-75dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-75dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-base-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-base-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-cyrillic-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-cyrillic-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-devel-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-devel-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-doc-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-doc-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-font-utils-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-font-utils-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-14-100dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-ISO8859-14-100dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-14-75dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-ISO8859-14-75dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-15-100dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-ISO8859-15-100dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-15-75dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-ISO8859-15-75dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-2-100dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-ISO8859-2-100dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-2-75dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-ISO8859-2-75dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-9-100dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-ISO8859-9-100dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-9-75dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-ISO8859-9-75dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-libs-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-libs-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-libs-data-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-libs-data-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-Mesa-libGL-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-Mesa-libGL-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-Mesa-libGLU-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-Mesa-libGLU-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-sdk-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-sdk-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-syriac-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-syriac-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-tools-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-tools-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-truetype-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-truetype-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-twm-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-twm-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-xauth-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-xauth-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-xdm-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-xdm-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-xfs-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-xfs-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-Xnest-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-Xnest-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-Xvfb-4.3.0-111.EL", release:"CentOS-3", cpu:"x86_64") )  faulty += '- XFree86-Xvfb-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-100dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-100dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-75dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-75dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-14-100dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-ISO8859-14-100dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-14-75dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-ISO8859-14-75dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-15-100dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-ISO8859-15-100dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-15-75dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-ISO8859-15-75dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-2-100dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-ISO8859-2-100dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-2-75dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-ISO8859-2-75dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-9-100dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-ISO8859-9-100dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-ISO8859-9-75dpi-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-ISO8859-9-75dpi-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-Mesa-libGL-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-Mesa-libGL-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-Mesa-libGLU-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-Mesa-libGLU-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-Xnest-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-Xnest-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-Xvfb-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-Xvfb-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-base-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-base-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-cyrillic-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-cyrillic-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-devel-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-devel-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-doc-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-doc-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-font-utils-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-font-utils-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-libs-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-libs-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-libs-data-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-libs-data-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-sdk-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-sdk-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-syriac-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-syriac-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-tools-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-tools-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-truetype-fonts-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-truetype-fonts-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-twm-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-twm-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-xauth-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-xauth-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-xdm-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-xdm-4.3.0-111.EL\n';
if ( rpm_check(reference:"XFree86-xfs-4.3.0-111.EL", release:"CentOS-3", cpu:"ia64") )  faulty += '- XFree86-xfs-4.3.0-111.EL\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
