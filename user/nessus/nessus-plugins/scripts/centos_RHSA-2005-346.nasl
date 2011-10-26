#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2005-346.

See also :

https://rhn.redhat.com/errata/RHSA-2005-346.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(21925);
 script_version("$Revision: 1.3 $");
 script_name(english:"CentOS : RHSA-2005-346");
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

if ( rpm_check(reference:"slocate-2.7-13.el4.6", release:"CentOS-4", cpu:"ia64") )  faulty += '- slocate-2.7-13.el4.6\n';
if ( rpm_check(reference:"slocate-2.7-13.el4.6", release:"CentOS-4", cpu:"i386") )  faulty += '- slocate-2.7-13.el4.6\n';
if ( rpm_check(reference:"slocate-2.7-13.el4.6", release:"CentOS-4", cpu:"x86_64") )  faulty += '- slocate-2.7-13.el4.6\n';
if ( rpm_check(reference:"ethereal-0.10.13-1.AS21.1", release:"CentOS-4", cpu:"i386") )  faulty += '- ethereal-0.10.13-1.AS21.1\n';
if ( rpm_check(reference:"ethereal-gnome-0.10.13-1.AS21.1", release:"CentOS-4", cpu:"i386") )  faulty += '- ethereal-gnome-0.10.13-1.AS21.1\n';
if ( rpm_check(reference:"fetchmail-5.9.0-21.7.3.el2.1.2", release:"CentOS-4", cpu:"i386") )  faulty += '- fetchmail-5.9.0-21.7.3.el2.1.2\n';
if ( rpm_check(reference:"fetchmailconf-5.9.0-21.7.3.el2.1.2", release:"CentOS-4", cpu:"i386") )  faulty += '- fetchmailconf-5.9.0-21.7.3.el2.1.2\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
