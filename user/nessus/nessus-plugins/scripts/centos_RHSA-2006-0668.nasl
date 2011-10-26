#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2006-0668.

See also :

https://rhn.redhat.com/errata/RHSA-2006-0668.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(22450);
 script_version("$Revision: 1.1 $");
 script_name(english:"CentOS : RHSA-2006-0668");
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

if ( rpm_check(reference:"squirrelmail-1.4.8-2.el3.centos.1", release:"CentOS-3") )  faulty += '- squirrelmail-1.4.8-2.el3.centos.1\n';
if ( rpm_check(reference:"squirrelmail-1.4.8-2.el4.centos4", release:"CentOS-4") )  faulty += '- squirrelmail-1.4.8-2.el4.centos4\n';
if ( rpm_check(reference:"php-4.1.2-2.11", release:"CentOS-3", cpu:"i386") )  faulty += '- php-4.1.2-2.11\n';
if ( rpm_check(reference:"php-devel-4.1.2-2.11", release:"CentOS-3", cpu:"i386") )  faulty += '- php-devel-4.1.2-2.11\n';
if ( rpm_check(reference:"php-imap-4.1.2-2.11", release:"CentOS-3", cpu:"i386") )  faulty += '- php-imap-4.1.2-2.11\n';
if ( rpm_check(reference:"php-ldap-4.1.2-2.11", release:"CentOS-3", cpu:"i386") )  faulty += '- php-ldap-4.1.2-2.11\n';
if ( rpm_check(reference:"php-manual-4.1.2-2.11", release:"CentOS-3", cpu:"i386") )  faulty += '- php-manual-4.1.2-2.11\n';
if ( rpm_check(reference:"php-mysql-4.1.2-2.11", release:"CentOS-3", cpu:"i386") )  faulty += '- php-mysql-4.1.2-2.11\n';
if ( rpm_check(reference:"php-odbc-4.1.2-2.11", release:"CentOS-3", cpu:"i386") )  faulty += '- php-odbc-4.1.2-2.11\n';
if ( rpm_check(reference:"php-pgsql-4.1.2-2.11", release:"CentOS-3", cpu:"i386") )  faulty += '- php-pgsql-4.1.2-2.11\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
