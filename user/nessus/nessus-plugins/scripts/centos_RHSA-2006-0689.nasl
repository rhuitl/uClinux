#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2006-0689.

See also :

https://rhn.redhat.com/errata/RHSA-2006-0689.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(22513);
 script_version("$Revision: 1.1 $");
 script_name(english:"CentOS : RHSA-2006-0689");
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

if ( rpm_check(reference:"kernel-doc-2.6.9-42.0.3.EL", release:"CentOS-4") )  faulty += '- kernel-doc-2.6.9-42.0.3.EL\n';
if ( rpm_check(reference:"openssh-3.1p1-21", release:"CentOS-4", cpu:"i386") )  faulty += '- openssh-3.1p1-21\n';
if ( rpm_check(reference:"openssh-askpass-3.1p1-21", release:"CentOS-4", cpu:"i386") )  faulty += '- openssh-askpass-3.1p1-21\n';
if ( rpm_check(reference:"openssh-askpass-gnome-3.1p1-21", release:"CentOS-4", cpu:"i386") )  faulty += '- openssh-askpass-gnome-3.1p1-21\n';
if ( rpm_check(reference:"openssh-clients-3.1p1-21", release:"CentOS-4", cpu:"i386") )  faulty += '- openssh-clients-3.1p1-21\n';
if ( rpm_check(reference:"openssh-server-3.1p1-21", release:"CentOS-4", cpu:"i386") )  faulty += '- openssh-server-3.1p1-21\n';
if ( rpm_check(reference:"openssl095a-0.9.5a-32", release:"CentOS-4", cpu:"i386") )  faulty += '- openssl095a-0.9.5a-32\n';
if ( rpm_check(reference:"openssl096-0.9.6-32", release:"CentOS-4", cpu:"i386") )  faulty += '- openssl096-0.9.6-32\n';
if ( rpm_check(reference:"openssl-0.9.6b-46", release:"CentOS-4", cpu:"i386") )  faulty += '- openssl-0.9.6b-46\n';
if ( rpm_check(reference:"openssl-devel-0.9.6b-46", release:"CentOS-4", cpu:"i386") )  faulty += '- openssl-devel-0.9.6b-46\n';
if ( rpm_check(reference:"openssl-perl-0.9.6b-46", release:"CentOS-4", cpu:"i386") )  faulty += '- openssl-perl-0.9.6b-46\n';
if ( rpm_check(reference:"openssl-0.9.6b-46", release:"CentOS-4", cpu:"i686") )  faulty += '- openssl-0.9.6b-46\n';
if ( rpm_check(reference:"kernel-2.6.9-42.0.3.EL", release:"CentOS-4", cpu:"x86_64") )  faulty += '- kernel-2.6.9-42.0.3.EL\n';
if ( rpm_check(reference:"kernel-devel-2.6.9-42.0.3.EL", release:"CentOS-4", cpu:"x86_64") )  faulty += '- kernel-devel-2.6.9-42.0.3.EL\n';
if ( rpm_check(reference:"kernel-largesmp-2.6.9-42.0.3.EL", release:"CentOS-4", cpu:"x86_64") )  faulty += '- kernel-largesmp-2.6.9-42.0.3.EL\n';
if ( rpm_check(reference:"kernel-largesmp-devel-2.6.9-42.0.3.EL", release:"CentOS-4", cpu:"x86_64") )  faulty += '- kernel-largesmp-devel-2.6.9-42.0.3.EL\n';
if ( rpm_check(reference:"kernel-smp-2.6.9-42.0.3.EL", release:"CentOS-4", cpu:"x86_64") )  faulty += '- kernel-smp-2.6.9-42.0.3.EL\n';
if ( rpm_check(reference:"kernel-smp-devel-2.6.9-42.0.3.EL", release:"CentOS-4", cpu:"x86_64") )  faulty += '- kernel-smp-devel-2.6.9-42.0.3.EL\n';
if ( rpm_check(reference:"kernel-2.6.9-42.0.3.EL", release:"CentOS-4", cpu:"i586") )  faulty += '- kernel-2.6.9-42.0.3.EL\n';
if ( rpm_check(reference:"kernel-2.6.9-42.0.3.EL", release:"CentOS-4", cpu:"i686") )  faulty += '- kernel-2.6.9-42.0.3.EL\n';
if ( rpm_check(reference:"kernel-devel-2.6.9-42.0.3.EL", release:"CentOS-4", cpu:"i586") )  faulty += '- kernel-devel-2.6.9-42.0.3.EL\n';
if ( rpm_check(reference:"kernel-devel-2.6.9-42.0.3.EL", release:"CentOS-4", cpu:"i686") )  faulty += '- kernel-devel-2.6.9-42.0.3.EL\n';
if ( rpm_check(reference:"kernel-hugemem-2.6.9-42.0.3.EL", release:"CentOS-4", cpu:"i686") )  faulty += '- kernel-hugemem-2.6.9-42.0.3.EL\n';
if ( rpm_check(reference:"kernel-hugemem-devel-2.6.9-42.0.3.EL", release:"CentOS-4", cpu:"i686") )  faulty += '- kernel-hugemem-devel-2.6.9-42.0.3.EL\n';
if ( rpm_check(reference:"kernel-smp-2.6.9-42.0.3.EL", release:"CentOS-4", cpu:"i586") )  faulty += '- kernel-smp-2.6.9-42.0.3.EL\n';
if ( rpm_check(reference:"kernel-smp-2.6.9-42.0.3.EL", release:"CentOS-4", cpu:"i686") )  faulty += '- kernel-smp-2.6.9-42.0.3.EL\n';
if ( rpm_check(reference:"kernel-smp-devel-2.6.9-42.0.3.EL", release:"CentOS-4", cpu:"i586") )  faulty += '- kernel-smp-devel-2.6.9-42.0.3.EL\n';
if ( rpm_check(reference:"kernel-smp-devel-2.6.9-42.0.3.EL", release:"CentOS-4", cpu:"i686") )  faulty += '- kernel-smp-devel-2.6.9-42.0.3.EL\n';
if ( rpm_check(reference:"php-4.1.2-2.12", release:"CentOS-4", cpu:"i386") )  faulty += '- php-4.1.2-2.12\n';
if ( rpm_check(reference:"php-devel-4.1.2-2.12", release:"CentOS-4", cpu:"i386") )  faulty += '- php-devel-4.1.2-2.12\n';
if ( rpm_check(reference:"php-imap-4.1.2-2.12", release:"CentOS-4", cpu:"i386") )  faulty += '- php-imap-4.1.2-2.12\n';
if ( rpm_check(reference:"php-ldap-4.1.2-2.12", release:"CentOS-4", cpu:"i386") )  faulty += '- php-ldap-4.1.2-2.12\n';
if ( rpm_check(reference:"php-manual-4.1.2-2.12", release:"CentOS-4", cpu:"i386") )  faulty += '- php-manual-4.1.2-2.12\n';
if ( rpm_check(reference:"php-mysql-4.1.2-2.12", release:"CentOS-4", cpu:"i386") )  faulty += '- php-mysql-4.1.2-2.12\n';
if ( rpm_check(reference:"php-odbc-4.1.2-2.12", release:"CentOS-4", cpu:"i386") )  faulty += '- php-odbc-4.1.2-2.12\n';
if ( rpm_check(reference:"php-pgsql-4.1.2-2.12", release:"CentOS-4", cpu:"i386") )  faulty += '- php-pgsql-4.1.2-2.12\n';
if ( rpm_check(reference:"kernel-2.6.9-42.0.3.EL", release:"CentOS-4", cpu:"ia64") )  faulty += '- kernel-2.6.9-42.0.3.EL\n';
if ( rpm_check(reference:"kernel-devel-2.6.9-42.0.3.EL", release:"CentOS-4", cpu:"ia64") )  faulty += '- kernel-devel-2.6.9-42.0.3.EL\n';
if ( rpm_check(reference:"kernel-largesmp-2.6.9-42.0.3.EL", release:"CentOS-4", cpu:"ia64") )  faulty += '- kernel-largesmp-2.6.9-42.0.3.EL\n';
if ( rpm_check(reference:"kernel-largesmp-devel-2.6.9-42.0.3.EL", release:"CentOS-4", cpu:"ia64") )  faulty += '- kernel-largesmp-devel-2.6.9-42.0.3.EL\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
