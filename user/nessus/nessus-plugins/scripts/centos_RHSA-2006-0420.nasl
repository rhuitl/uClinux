#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2006-0420.

See also :

https://rhn.redhat.com/errata/RHSA-2006-0420.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(21899);
 script_version("$Revision: 1.4 $");
 script_name(english:"CentOS : RHSA-2006-0420");
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

if ( rpm_check(reference:"ethereal-0.99.0-EL3.2", release:"CentOS-3", cpu:"i386") )  faulty += '- ethereal-0.99.0-EL3.2\n';
if ( rpm_check(reference:"ethereal-gnome-0.99.0-EL3.2", release:"CentOS-3", cpu:"i386") )  faulty += '- ethereal-gnome-0.99.0-EL3.2\n';
if ( rpm_check(reference:"ethereal-0.99.0-EL3.2", release:"CentOS-3", cpu:"x86_64") )  faulty += '- ethereal-0.99.0-EL3.2\n';
if ( rpm_check(reference:"ethereal-gnome-0.99.0-EL3.2", release:"CentOS-3", cpu:"x86_64") )  faulty += '- ethereal-gnome-0.99.0-EL3.2\n';
if ( rpm_check(reference:"ethereal-0.99.0-EL4.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- ethereal-0.99.0-EL4.2\n';
if ( rpm_check(reference:"ethereal-gnome-0.99.0-EL4.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- ethereal-gnome-0.99.0-EL4.2\n';
if ( rpm_check(reference:"ethereal-0.99.0-EL3.2", release:"CentOS-3", cpu:"ia64") )  faulty += '- ethereal-0.99.0-EL3.2\n';
if ( rpm_check(reference:"ethereal-gnome-0.99.0-EL3.2", release:"CentOS-3", cpu:"ia64") )  faulty += '- ethereal-gnome-0.99.0-EL3.2\n';
if ( rpm_check(reference:"ethereal-gnome-0.99.0-EL4.2", release:"CentOS-4", cpu:"i386") )  faulty += '- ethereal-gnome-0.99.0-EL4.2\n';
if ( rpm_check(reference:"ethereal-0.99.0-EL4.2", release:"CentOS-4", cpu:"i386") )  faulty += '- ethereal-0.99.0-EL4.2\n';
if ( rpm_check(reference:"ethereal-gnome-0.99.0-EL4.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- ethereal-gnome-0.99.0-EL4.2\n';
if ( rpm_check(reference:"ethereal-0.99.0-EL4.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- ethereal-0.99.0-EL4.2\n';
if ( rpm_check(reference:"dia-0.88.1-3.3", release:"CentOS-4", cpu:"i386") )  faulty += '- dia-0.88.1-3.3\n';
if ( rpm_check(reference:"ethereal-0.99.0-AS21.2", release:"CentOS-4", cpu:"i386") )  faulty += '- ethereal-0.99.0-AS21.2\n';
if ( rpm_check(reference:"ethereal-gnome-0.99.0-AS21.2", release:"CentOS-4", cpu:"i386") )  faulty += '- ethereal-gnome-0.99.0-AS21.2\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
