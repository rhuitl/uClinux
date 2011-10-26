#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2006-0264.

See also :

https://rhn.redhat.com/errata/RHSA-2006-0264.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(21893);
 script_version("$Revision: 1.4 $");
 script_name(english:"CentOS : RHSA-2006-0264");
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

if ( rpm_check(reference:"gnupg-1.0.7-16", release:"CentOS-3", cpu:"i386") )  faulty += '- gnupg-1.0.7-16\n';
if ( rpm_check(reference:"glibc-2.2.4-32.23", release:"CentOS-3", cpu:"i386") )  faulty += '- glibc-2.2.4-32.23\n';
if ( rpm_check(reference:"glibc-common-2.2.4-32.23", release:"CentOS-3", cpu:"i386") )  faulty += '- glibc-common-2.2.4-32.23\n';
if ( rpm_check(reference:"glibc-devel-2.2.4-32.23", release:"CentOS-3", cpu:"i386") )  faulty += '- glibc-devel-2.2.4-32.23\n';
if ( rpm_check(reference:"glibc-profile-2.2.4-32.23", release:"CentOS-3", cpu:"i386") )  faulty += '- glibc-profile-2.2.4-32.23\n';
if ( rpm_check(reference:"nscd-2.2.4-32.23", release:"CentOS-3", cpu:"i386") )  faulty += '- nscd-2.2.4-32.23\n';
if ( rpm_check(reference:"glibc-2.2.4-32.23", release:"CentOS-3", cpu:"i686") )  faulty += '- glibc-2.2.4-32.23\n';
if ( rpm_check(reference:"bash-2.05-8.6", release:"CentOS-3", cpu:"i386") )  faulty += '- bash-2.05-8.6\n';
if ( rpm_check(reference:"bash-doc-2.05-8.6", release:"CentOS-3", cpu:"i386") )  faulty += '- bash-doc-2.05-8.6\n';
if ( rpm_check(reference:"dos2unix-3.1-7.EL.22", release:"CentOS-3", cpu:"i386") )  faulty += '- dos2unix-3.1-7.EL.22\n';
if ( rpm_check(reference:"unix2dos-2.2-12.EL.25", release:"CentOS-3", cpu:"i386") )  faulty += '- unix2dos-2.2-12.EL.25\n';
if ( rpm_check(reference:"sendmail-8.12.11-4.RHEL3.4", release:"CentOS-3", cpu:"i386") )  faulty += '- sendmail-8.12.11-4.RHEL3.4\n';
if ( rpm_check(reference:"sendmail-cf-8.12.11-4.RHEL3.4", release:"CentOS-3", cpu:"i386") )  faulty += '- sendmail-cf-8.12.11-4.RHEL3.4\n';
if ( rpm_check(reference:"sendmail-devel-8.12.11-4.RHEL3.4", release:"CentOS-3", cpu:"i386") )  faulty += '- sendmail-devel-8.12.11-4.RHEL3.4\n';
if ( rpm_check(reference:"sendmail-doc-8.12.11-4.RHEL3.4", release:"CentOS-3", cpu:"i386") )  faulty += '- sendmail-doc-8.12.11-4.RHEL3.4\n';
if ( rpm_check(reference:"sendmail-8.12.11-4.RHEL3.4", release:"CentOS-3", cpu:"x86_64") )  faulty += '- sendmail-8.12.11-4.RHEL3.4\n';
if ( rpm_check(reference:"sendmail-cf-8.12.11-4.RHEL3.4", release:"CentOS-3", cpu:"x86_64") )  faulty += '- sendmail-cf-8.12.11-4.RHEL3.4\n';
if ( rpm_check(reference:"sendmail-devel-8.12.11-4.RHEL3.4", release:"CentOS-3", cpu:"x86_64") )  faulty += '- sendmail-devel-8.12.11-4.RHEL3.4\n';
if ( rpm_check(reference:"sendmail-doc-8.12.11-4.RHEL3.4", release:"CentOS-3", cpu:"x86_64") )  faulty += '- sendmail-doc-8.12.11-4.RHEL3.4\n';
if ( rpm_check(reference:"sendmail-8.12.11-4.RHEL3.4", release:"CentOS-3", cpu:"ia64") )  faulty += '- sendmail-8.12.11-4.RHEL3.4\n';
if ( rpm_check(reference:"sendmail-cf-8.12.11-4.RHEL3.4", release:"CentOS-3", cpu:"ia64") )  faulty += '- sendmail-cf-8.12.11-4.RHEL3.4\n';
if ( rpm_check(reference:"sendmail-devel-8.12.11-4.RHEL3.4", release:"CentOS-3", cpu:"ia64") )  faulty += '- sendmail-devel-8.12.11-4.RHEL3.4\n';
if ( rpm_check(reference:"sendmail-doc-8.12.11-4.RHEL3.4", release:"CentOS-3", cpu:"ia64") )  faulty += '- sendmail-doc-8.12.11-4.RHEL3.4\n';
if ( rpm_check(reference:"sendmail-8.13.1-3.RHEL4.3", release:"CentOS-4", cpu:"ia64") )  faulty += '- sendmail-8.13.1-3.RHEL4.3\n';
if ( rpm_check(reference:"sendmail-cf-8.13.1-3.RHEL4.3", release:"CentOS-4", cpu:"ia64") )  faulty += '- sendmail-cf-8.13.1-3.RHEL4.3\n';
if ( rpm_check(reference:"sendmail-devel-8.13.1-3.RHEL4.3", release:"CentOS-4", cpu:"ia64") )  faulty += '- sendmail-devel-8.13.1-3.RHEL4.3\n';
if ( rpm_check(reference:"sendmail-doc-8.13.1-3.RHEL4.3", release:"CentOS-4", cpu:"ia64") )  faulty += '- sendmail-doc-8.13.1-3.RHEL4.3\n';
if ( rpm_check(reference:"sendmail-8.13.1-3.RHEL4.3", release:"CentOS-4", cpu:"x86_64") )  faulty += '- sendmail-8.13.1-3.RHEL4.3\n';
if ( rpm_check(reference:"sendmail-cf-8.13.1-3.RHEL4.3", release:"CentOS-4", cpu:"x86_64") )  faulty += '- sendmail-cf-8.13.1-3.RHEL4.3\n';
if ( rpm_check(reference:"sendmail-devel-8.13.1-3.RHEL4.3", release:"CentOS-4", cpu:"x86_64") )  faulty += '- sendmail-devel-8.13.1-3.RHEL4.3\n';
if ( rpm_check(reference:"sendmail-doc-8.13.1-3.RHEL4.3", release:"CentOS-4", cpu:"x86_64") )  faulty += '- sendmail-doc-8.13.1-3.RHEL4.3\n';
if ( rpm_check(reference:"sendmail-8.13.1-3.RHEL4.3", release:"CentOS-4", cpu:"i386") )  faulty += '- sendmail-8.13.1-3.RHEL4.3\n';
if ( rpm_check(reference:"sendmail-cf-8.13.1-3.RHEL4.3", release:"CentOS-4", cpu:"i386") )  faulty += '- sendmail-cf-8.13.1-3.RHEL4.3\n';
if ( rpm_check(reference:"sendmail-devel-8.13.1-3.RHEL4.3", release:"CentOS-4", cpu:"i386") )  faulty += '- sendmail-devel-8.13.1-3.RHEL4.3\n';
if ( rpm_check(reference:"sendmail-doc-8.13.1-3.RHEL4.3", release:"CentOS-4", cpu:"i386") )  faulty += '- sendmail-doc-8.13.1-3.RHEL4.3\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
