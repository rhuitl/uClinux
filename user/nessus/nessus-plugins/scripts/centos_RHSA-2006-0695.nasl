#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2006-0695.

See also :

https://rhn.redhat.com/errata/RHSA-2006-0695.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(22484);
 script_version("$Revision: 1.1 $");
 script_name(english:"CentOS : RHSA-2006-0695");
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

if ( rpm_check(reference:"openssl-0.9.7a-33.21", release:"CentOS-3", cpu:"ia64") )  faulty += '- openssl-0.9.7a-33.21\n';
if ( rpm_check(reference:"openssl-devel-0.9.7a-33.21", release:"CentOS-3", cpu:"ia64") )  faulty += '- openssl-devel-0.9.7a-33.21\n';
if ( rpm_check(reference:"openssl-perl-0.9.7a-33.21", release:"CentOS-3", cpu:"ia64") )  faulty += '- openssl-perl-0.9.7a-33.21\n';
if ( rpm_check(reference:"openssl096b-0.9.6b-16.46", release:"CentOS-3", cpu:"ia64") )  faulty += '- openssl096b-0.9.6b-16.46\n';
if ( rpm_check(reference:"openssl096b-0.9.6b-16.46", release:"CentOS-3", cpu:"i386") )  faulty += '- openssl096b-0.9.6b-16.46\n';
if ( rpm_check(reference:"openssl-0.9.7a-33.21", release:"CentOS-3", cpu:"i386") )  faulty += '- openssl-0.9.7a-33.21\n';
if ( rpm_check(reference:"openssl-0.9.7a-33.21", release:"CentOS-3", cpu:"i686") )  faulty += '- openssl-0.9.7a-33.21\n';
if ( rpm_check(reference:"openssl-devel-0.9.7a-33.21", release:"CentOS-3", cpu:"i386") )  faulty += '- openssl-devel-0.9.7a-33.21\n';
if ( rpm_check(reference:"openssl-perl-0.9.7a-33.21", release:"CentOS-3", cpu:"i386") )  faulty += '- openssl-perl-0.9.7a-33.21\n';
if ( rpm_check(reference:"openssl096b-0.9.6b-16.46", release:"CentOS-3", cpu:"x86_64") )  faulty += '- openssl096b-0.9.6b-16.46\n';
if ( rpm_check(reference:"openssl-0.9.7a-33.21", release:"CentOS-3", cpu:"x86_64") )  faulty += '- openssl-0.9.7a-33.21\n';
if ( rpm_check(reference:"openssl-devel-0.9.7a-33.21", release:"CentOS-3", cpu:"x86_64") )  faulty += '- openssl-devel-0.9.7a-33.21\n';
if ( rpm_check(reference:"openssl-perl-0.9.7a-33.21", release:"CentOS-3", cpu:"x86_64") )  faulty += '- openssl-perl-0.9.7a-33.21\n';
if ( rpm_check(reference:"openssl096b-0.9.6b-22.46", release:"CentOS-4", cpu:"i386") )  faulty += '- openssl096b-0.9.6b-22.46\n';
if ( rpm_check(reference:"openssl096b-0.9.6b-22.46", release:"CentOS-4", cpu:"x86_64") )  faulty += '- openssl096b-0.9.6b-22.46\n';
if ( rpm_check(reference:"openssl-0.9.7a-43.14", release:"CentOS-4", cpu:"i686") )  faulty += '- openssl-0.9.7a-43.14\n';
if ( rpm_check(reference:"openssl-0.9.7a-43.14", release:"CentOS-4", cpu:"x86_64") )  faulty += '- openssl-0.9.7a-43.14\n';
if ( rpm_check(reference:"openssl-devel-0.9.7a-43.14", release:"CentOS-4", cpu:"x86_64") )  faulty += '- openssl-devel-0.9.7a-43.14\n';
if ( rpm_check(reference:"openssl-perl-0.9.7a-43.14", release:"CentOS-4", cpu:"x86_64") )  faulty += '- openssl-perl-0.9.7a-43.14\n';
if ( rpm_check(reference:"openssl-0.9.7a-43.14", release:"CentOS-4", cpu:"i386") )  faulty += '- openssl-0.9.7a-43.14\n';
if ( rpm_check(reference:"openssl-0.9.7a-43.14", release:"CentOS-4", cpu:"i586") )  faulty += '- openssl-0.9.7a-43.14\n';
if ( rpm_check(reference:"openssl-devel-0.9.7a-43.14", release:"CentOS-4", cpu:"i386") )  faulty += '- openssl-devel-0.9.7a-43.14\n';
if ( rpm_check(reference:"openssl-devel-0.9.7a-43.14", release:"CentOS-4", cpu:"i586") )  faulty += '- openssl-devel-0.9.7a-43.14\n';
if ( rpm_check(reference:"openssl-perl-0.9.7a-43.14", release:"CentOS-4", cpu:"i386") )  faulty += '- openssl-perl-0.9.7a-43.14\n';
if ( rpm_check(reference:"openssl-perl-0.9.7a-43.14", release:"CentOS-4", cpu:"i586") )  faulty += '- openssl-perl-0.9.7a-43.14\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
