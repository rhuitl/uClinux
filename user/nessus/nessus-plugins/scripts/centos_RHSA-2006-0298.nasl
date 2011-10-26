#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2006-0298.

See also :

https://rhn.redhat.com/errata/RHSA-2006-0298.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(22134);
 script_version("$Revision: 1.1 $");
 script_name(english:"CentOS : RHSA-2006-0298");
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

if ( rpm_check(reference:"openssh-3.6.1p2-33.30.9", release:"CentOS-3", cpu:"ia64") )  faulty += '- openssh-3.6.1p2-33.30.9\n';
if ( rpm_check(reference:"openssh-askpass-3.6.1p2-33.30.9", release:"CentOS-3", cpu:"ia64") )  faulty += '- openssh-askpass-3.6.1p2-33.30.9\n';
if ( rpm_check(reference:"openssh-askpass-gnome-3.6.1p2-33.30.9", release:"CentOS-3", cpu:"ia64") )  faulty += '- openssh-askpass-gnome-3.6.1p2-33.30.9\n';
if ( rpm_check(reference:"openssh-clients-3.6.1p2-33.30.9", release:"CentOS-3", cpu:"ia64") )  faulty += '- openssh-clients-3.6.1p2-33.30.9\n';
if ( rpm_check(reference:"openssh-server-3.6.1p2-33.30.9", release:"CentOS-3", cpu:"ia64") )  faulty += '- openssh-server-3.6.1p2-33.30.9\n';
if ( rpm_check(reference:"libtiff-3.5.7-30.el2.4", release:"CentOS-3", cpu:"i386") )  faulty += '- libtiff-3.5.7-30.el2.4\n';
if ( rpm_check(reference:"libtiff-devel-3.5.7-30.el2.4", release:"CentOS-3", cpu:"i386") )  faulty += '- libtiff-devel-3.5.7-30.el2.4\n';
if ( rpm_check(reference:"gnupg-1.0.7-18", release:"CentOS-3", cpu:"i386") )  faulty += '- gnupg-1.0.7-18\n';
if ( rpm_check(reference:"openssh-3.6.1p2-33.30.9", release:"CentOS-3", cpu:"i386") )  faulty += '- openssh-3.6.1p2-33.30.9\n';
if ( rpm_check(reference:"openssh-askpass-3.6.1p2-33.30.9", release:"CentOS-3", cpu:"i386") )  faulty += '- openssh-askpass-3.6.1p2-33.30.9\n';
if ( rpm_check(reference:"openssh-askpass-gnome-3.6.1p2-33.30.9", release:"CentOS-3", cpu:"i386") )  faulty += '- openssh-askpass-gnome-3.6.1p2-33.30.9\n';
if ( rpm_check(reference:"openssh-clients-3.6.1p2-33.30.9", release:"CentOS-3", cpu:"i386") )  faulty += '- openssh-clients-3.6.1p2-33.30.9\n';
if ( rpm_check(reference:"openssh-server-3.6.1p2-33.30.9", release:"CentOS-3", cpu:"i386") )  faulty += '- openssh-server-3.6.1p2-33.30.9\n';
if ( rpm_check(reference:"openssh-3.6.1p2-33.30.9", release:"CentOS-3", cpu:"x86_64") )  faulty += '- openssh-3.6.1p2-33.30.9\n';
if ( rpm_check(reference:"openssh-askpass-3.6.1p2-33.30.9", release:"CentOS-3", cpu:"x86_64") )  faulty += '- openssh-askpass-3.6.1p2-33.30.9\n';
if ( rpm_check(reference:"openssh-askpass-gnome-3.6.1p2-33.30.9", release:"CentOS-3", cpu:"x86_64") )  faulty += '- openssh-askpass-gnome-3.6.1p2-33.30.9\n';
if ( rpm_check(reference:"openssh-clients-3.6.1p2-33.30.9", release:"CentOS-3", cpu:"x86_64") )  faulty += '- openssh-clients-3.6.1p2-33.30.9\n';
if ( rpm_check(reference:"openssh-server-3.6.1p2-33.30.9", release:"CentOS-3", cpu:"x86_64") )  faulty += '- openssh-server-3.6.1p2-33.30.9\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
