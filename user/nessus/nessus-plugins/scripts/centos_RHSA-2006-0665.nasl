#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2006-0665.

See also :

https://rhn.redhat.com/errata/RHSA-2006-0665.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(22339);
 script_version("$Revision: 1.1 $");
 script_name(english:"CentOS : RHSA-2006-0665");
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

if ( rpm_check(reference:"xorg-x11-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-Mesa-libGL-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-Mesa-libGL-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-Mesa-libGLU-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-Mesa-libGLU-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-Xdmx-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-Xdmx-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-Xnest-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-Xnest-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-Xvfb-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-Xvfb-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-deprecated-libs-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-deprecated-libs-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-deprecated-libs-devel-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-deprecated-libs-devel-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-devel-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-devel-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-doc-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-doc-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-font-utils-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-font-utils-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-libs-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-libs-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-sdk-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-sdk-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-tools-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-tools-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-twm-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-twm-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-xauth-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-xauth-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-xdm-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-xdm-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-xfs-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- xorg-x11-xfs-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-deprecated-libs-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-deprecated-libs-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-deprecated-libs-devel-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-deprecated-libs-devel-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-devel-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-devel-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-doc-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-doc-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-font-utils-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-font-utils-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-libs-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-libs-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-Mesa-libGL-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-Mesa-libGL-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-Mesa-libGLU-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-Mesa-libGLU-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-sdk-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-sdk-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-tools-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-tools-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-twm-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-twm-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-xauth-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-xauth-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-xdm-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-xdm-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-Xdmx-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-Xdmx-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-xfs-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-xfs-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-Xnest-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-Xnest-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-Xvfb-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- xorg-x11-Xvfb-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-Mesa-libGL-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-Mesa-libGL-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-Mesa-libGLU-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-Mesa-libGLU-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-deprecated-libs-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-deprecated-libs-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-devel-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-devel-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-libs-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-libs-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-deprecated-libs-devel-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-deprecated-libs-devel-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-doc-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-doc-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-font-utils-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-font-utils-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-sdk-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-sdk-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-tools-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-tools-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-twm-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-twm-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-xauth-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-xauth-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-xdm-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-xdm-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-Xdmx-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-Xdmx-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-xfs-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-xfs-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-Xnest-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-Xnest-6.8.2-1.EL.13.37.2\n';
if ( rpm_check(reference:"xorg-x11-Xvfb-6.8.2-1.EL.13.37.2", release:"CentOS-4", cpu:"i386") )  faulty += '- xorg-x11-Xvfb-6.8.2-1.EL.13.37.2\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
