#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2006-0232.

See also :

https://rhn.redhat.com/errata/RHSA-2006-0232.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(21988);
 script_version("$Revision: 1.3 $");
 script_name(english:"CentOS : RHSA-2006-0232");
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

if ( rpm_check(reference:"tar-1.14-9.RHEL4", release:"CentOS-4", cpu:"ia64") )  faulty += '- tar-1.14-9.RHEL4\n';
if ( rpm_check(reference:"tar-1.14-9.RHEL4", release:"CentOS-4", cpu:"i386") )  faulty += '- tar-1.14-9.RHEL4\n';
if ( rpm_check(reference:"tar-1.14-9.RHEL4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- tar-1.14-9.RHEL4\n';
if ( rpm_check(reference:"sendmail-8.12.11-4.21AS.8", release:"CentOS-4", cpu:"i386") )  faulty += '- sendmail-8.12.11-4.21AS.8\n';
if ( rpm_check(reference:"sendmail-cf-8.12.11-4.21AS.8", release:"CentOS-4", cpu:"i386") )  faulty += '- sendmail-cf-8.12.11-4.21AS.8\n';
if ( rpm_check(reference:"sendmail-devel-8.12.11-4.21AS.8", release:"CentOS-4", cpu:"i386") )  faulty += '- sendmail-devel-8.12.11-4.21AS.8\n';
if ( rpm_check(reference:"sendmail-doc-8.12.11-4.21AS.8", release:"CentOS-4", cpu:"i386") )  faulty += '- sendmail-doc-8.12.11-4.21AS.8\n';
if ( rpm_check(reference:"ypserv-2.8-9.23", release:"CentOS-4", cpu:"i386") )  faulty += '- ypserv-2.8-9.23\n';
if ( rpm_check(reference:"krb5-devel-1.2.2-40", release:"CentOS-4", cpu:"i386") )  faulty += '- krb5-devel-1.2.2-40\n';
if ( rpm_check(reference:"krb5-libs-1.2.2-40", release:"CentOS-4", cpu:"i386") )  faulty += '- krb5-libs-1.2.2-40\n';
if ( rpm_check(reference:"krb5-server-1.2.2-40", release:"CentOS-4", cpu:"i386") )  faulty += '- krb5-server-1.2.2-40\n';
if ( rpm_check(reference:"krb5-workstation-1.2.2-40", release:"CentOS-4", cpu:"i386") )  faulty += '- krb5-workstation-1.2.2-40\n';
if ( rpm_check(reference:"emacs-20.7-41.3", release:"CentOS-4", cpu:"i386") )  faulty += '- emacs-20.7-41.3\n';
if ( rpm_check(reference:"emacs-el-20.7-41.3", release:"CentOS-4", cpu:"i386") )  faulty += '- emacs-el-20.7-41.3\n';
if ( rpm_check(reference:"emacs-leim-20.7-41.3", release:"CentOS-4", cpu:"i386") )  faulty += '- emacs-leim-20.7-41.3\n';
if ( rpm_check(reference:"emacs-nox-20.7-41.3", release:"CentOS-4", cpu:"i386") )  faulty += '- emacs-nox-20.7-41.3\n';
if ( rpm_check(reference:"emacs-X11-20.7-41.3", release:"CentOS-4", cpu:"i386") )  faulty += '- emacs-X11-20.7-41.3\n';
if ( rpm_check(reference:"nss_db-2.2-13.1.3", release:"CentOS-4", cpu:"i386") )  faulty += '- nss_db-2.2-13.1.3\n';
if ( rpm_check(reference:"nss_db-compat-2.2-13.1.3", release:"CentOS-4", cpu:"i386") )  faulty += '- nss_db-compat-2.2-13.1.3\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
