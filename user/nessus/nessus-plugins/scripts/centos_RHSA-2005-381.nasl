#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2005-381.

See also :

https://rhn.redhat.com/errata/RHSA-2005-381.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(21816);
 script_version("$Revision: 1.4 $");
 script_name(english:"CentOS : RHSA-2005-381");
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

if ( rpm_check(reference:"xinitrc-3.20.2-1", release:"CentOS-4") )  faulty += '- xinitrc-3.20.2-1\n';
if ( rpm_check(reference:"man-pages-ja-20041215-1.EL2.1.0", release:"CentOS-4") )  faulty += '- man-pages-ja-20041215-1.EL2.1.0\n';
if ( rpm_check(reference:"centos-yumconf-4-4.2", release:"CentOS-2") )  faulty += '- centos-yumconf-4-4.2\n';
if ( rpm_check(reference:"dialog-0.9a-5.1.AS21", release:"CentOS-4", cpu:"i386") )  faulty += '- dialog-0.9a-5.1.AS21\n';
if ( rpm_check(reference:"util-linux-2.11f-20.6", release:"CentOS-4", cpu:"i386") )  faulty += '- util-linux-2.11f-20.6\n';
if ( rpm_check(reference:"psmisc-20.1-3", release:"CentOS-4", cpu:"i386") )  faulty += '- psmisc-20.1-3\n';
if ( rpm_check(reference:"procps-2.0.7-11.23", release:"CentOS-4", cpu:"i386") )  faulty += '- procps-2.0.7-11.23\n';
if ( rpm_check(reference:"procps-X11-2.0.7-11.23", release:"CentOS-4", cpu:"i386") )  faulty += '- procps-X11-2.0.7-11.23\n';
if ( rpm_check(reference:"net-tools-1.60-19.AS21.3", release:"CentOS-4", cpu:"i386") )  faulty += '- net-tools-1.60-19.AS21.3\n';
if ( rpm_check(reference:"logrotate-3.5.9-2", release:"CentOS-4", cpu:"i386") )  faulty += '- logrotate-3.5.9-2\n';
if ( rpm_check(reference:"amanda-2.4.4p3-1.21as.1", release:"CentOS-4", cpu:"i386") )  faulty += '- amanda-2.4.4p3-1.21as.1\n';
if ( rpm_check(reference:"amanda-client-2.4.4p3-1.21as.1", release:"CentOS-4", cpu:"i386") )  faulty += '- amanda-client-2.4.4p3-1.21as.1\n';
if ( rpm_check(reference:"amanda-devel-2.4.4p3-1.21as.1", release:"CentOS-4", cpu:"i386") )  faulty += '- amanda-devel-2.4.4p3-1.21as.1\n';
if ( rpm_check(reference:"amanda-server-2.4.4p3-1.21as.1", release:"CentOS-4", cpu:"i386") )  faulty += '- amanda-server-2.4.4p3-1.21as.1\n';
if ( rpm_check(reference:"pam-0.75-46.64", release:"CentOS-4", cpu:"i386") )  faulty += '- pam-0.75-46.64\n';
if ( rpm_check(reference:"pam-devel-0.75-46.64", release:"CentOS-4", cpu:"i386") )  faulty += '- pam-devel-0.75-46.64\n';
if ( rpm_check(reference:"chkconfig-1.3.13.2-0.2.1", release:"CentOS-4", cpu:"i386") )  faulty += '- chkconfig-1.3.13.2-0.2.1\n';
if ( rpm_check(reference:"ntsysv-1.3.13.2-0.2.1", release:"CentOS-4", cpu:"i386") )  faulty += '- ntsysv-1.3.13.2-0.2.1\n';
if ( rpm_check(reference:"initscripts-6.47.14-1.c2.1", release:"CentOS-4", cpu:"i386") )  faulty += '- initscripts-6.47.14-1.c2.1\n';
if ( rpm_check(reference:"raidtools-1.00.3-8.EL2.1", release:"CentOS-4", cpu:"i386") )  faulty += '- raidtools-1.00.3-8.EL2.1\n';
if ( rpm_check(reference:"libtiff-3.5.7-29.el2", release:"CentOS-4", cpu:"i386") )  faulty += '- libtiff-3.5.7-29.el2\n';
if ( rpm_check(reference:"libtiff-devel-3.5.7-29.el2", release:"CentOS-4", cpu:"i386") )  faulty += '- libtiff-devel-3.5.7-29.el2\n';
if ( rpm_check(reference:"postgresql-7.1.3-7.rhel2.1AS", release:"CentOS-4", cpu:"i386") )  faulty += '- postgresql-7.1.3-7.rhel2.1AS\n';
if ( rpm_check(reference:"postgresql-contrib-7.1.3-7.rhel2.1AS", release:"CentOS-4", cpu:"i386") )  faulty += '- postgresql-contrib-7.1.3-7.rhel2.1AS\n';
if ( rpm_check(reference:"postgresql-devel-7.1.3-7.rhel2.1AS", release:"CentOS-4", cpu:"i386") )  faulty += '- postgresql-devel-7.1.3-7.rhel2.1AS\n';
if ( rpm_check(reference:"postgresql-docs-7.1.3-7.rhel2.1AS", release:"CentOS-4", cpu:"i386") )  faulty += '- postgresql-docs-7.1.3-7.rhel2.1AS\n';
if ( rpm_check(reference:"postgresql-jdbc-7.1.3-7.rhel2.1AS", release:"CentOS-4", cpu:"i386") )  faulty += '- postgresql-jdbc-7.1.3-7.rhel2.1AS\n';
if ( rpm_check(reference:"postgresql-libs-7.1.3-7.rhel2.1AS", release:"CentOS-4", cpu:"i386") )  faulty += '- postgresql-libs-7.1.3-7.rhel2.1AS\n';
if ( rpm_check(reference:"postgresql-odbc-7.1.3-7.rhel2.1AS", release:"CentOS-4", cpu:"i386") )  faulty += '- postgresql-odbc-7.1.3-7.rhel2.1AS\n';
if ( rpm_check(reference:"postgresql-perl-7.1.3-7.rhel2.1AS", release:"CentOS-4", cpu:"i386") )  faulty += '- postgresql-perl-7.1.3-7.rhel2.1AS\n';
if ( rpm_check(reference:"postgresql-python-7.1.3-7.rhel2.1AS", release:"CentOS-4", cpu:"i386") )  faulty += '- postgresql-python-7.1.3-7.rhel2.1AS\n';
if ( rpm_check(reference:"postgresql-server-7.1.3-7.rhel2.1AS", release:"CentOS-4", cpu:"i386") )  faulty += '- postgresql-server-7.1.3-7.rhel2.1AS\n';
if ( rpm_check(reference:"postgresql-tcl-7.1.3-7.rhel2.1AS", release:"CentOS-4", cpu:"i386") )  faulty += '- postgresql-tcl-7.1.3-7.rhel2.1AS\n';
if ( rpm_check(reference:"postgresql-test-7.1.3-7.rhel2.1AS", release:"CentOS-4", cpu:"i386") )  faulty += '- postgresql-test-7.1.3-7.rhel2.1AS\n';
if ( rpm_check(reference:"postgresql-tk-7.1.3-7.rhel2.1AS", release:"CentOS-4", cpu:"i386") )  faulty += '- postgresql-tk-7.1.3-7.rhel2.1AS\n';
if ( rpm_check(reference:"lsof-4.51-2.1", release:"CentOS-4", cpu:"i386") )  faulty += '- lsof-4.51-2.1\n';
if ( rpm_check(reference:"mt-st-0.6-3", release:"CentOS-4", cpu:"i386") )  faulty += '- mt-st-0.6-3\n';
if ( rpm_check(reference:"nasm-0.98.38-3.EL4", release:"CentOS-4", cpu:"ia64") )  faulty += '- nasm-0.98.38-3.EL4\n';
if ( rpm_check(reference:"nasm-doc-0.98.38-3.EL4", release:"CentOS-4", cpu:"ia64") )  faulty += '- nasm-doc-0.98.38-3.EL4\n';
if ( rpm_check(reference:"nasm-rdoff-0.98.38-3.EL4", release:"CentOS-4", cpu:"ia64") )  faulty += '- nasm-rdoff-0.98.38-3.EL4\n';
if ( rpm_check(reference:"nasm-0.98.35-3.EL3", release:"CentOS-3", cpu:"ia64") )  faulty += '- nasm-0.98.35-3.EL3\n';
if ( rpm_check(reference:"nasm-doc-0.98.35-3.EL3", release:"CentOS-3", cpu:"ia64") )  faulty += '- nasm-doc-0.98.35-3.EL3\n';
if ( rpm_check(reference:"nasm-rdoff-0.98.35-3.EL3", release:"CentOS-3", cpu:"ia64") )  faulty += '- nasm-rdoff-0.98.35-3.EL3\n';
if ( rpm_check(reference:"nasm-0.98.35-3.EL3", release:"CentOS-3", cpu:"i386") )  faulty += '- nasm-0.98.35-3.EL3\n';
if ( rpm_check(reference:"nasm-doc-0.98.35-3.EL3", release:"CentOS-3", cpu:"i386") )  faulty += '- nasm-doc-0.98.35-3.EL3\n';
if ( rpm_check(reference:"nasm-rdoff-0.98.35-3.EL3", release:"CentOS-3", cpu:"i386") )  faulty += '- nasm-rdoff-0.98.35-3.EL3\n';
if ( rpm_check(reference:"nasm-0.98.35-3.EL3", release:"CentOS-3", cpu:"x86_64") )  faulty += '- nasm-0.98.35-3.EL3\n';
if ( rpm_check(reference:"nasm-doc-0.98.35-3.EL3", release:"CentOS-3", cpu:"x86_64") )  faulty += '- nasm-doc-0.98.35-3.EL3\n';
if ( rpm_check(reference:"nasm-rdoff-0.98.35-3.EL3", release:"CentOS-3", cpu:"x86_64") )  faulty += '- nasm-rdoff-0.98.35-3.EL3\n';
if ( rpm_check(reference:"php-4.3.9-3.6", release:"CentOS-2", cpu:"i386") )  faulty += '- php-4.3.9-3.6\n';
if ( rpm_check(reference:"php-ldap-4.3.9-3.6", release:"CentOS-2", cpu:"i386") )  faulty += '- php-ldap-4.3.9-3.6\n';
if ( rpm_check(reference:"php-pear-4.3.9-3.6", release:"CentOS-2", cpu:"i386") )  faulty += '- php-pear-4.3.9-3.6\n';
if ( rpm_check(reference:"php-devel-4.3.9-3.6", release:"CentOS-2", cpu:"i386") )  faulty += '- php-devel-4.3.9-3.6\n';
if ( rpm_check(reference:"php-mbstring-4.3.9-3.6", release:"CentOS-2", cpu:"i386") )  faulty += '- php-mbstring-4.3.9-3.6\n';
if ( rpm_check(reference:"php-pgsql-4.3.9-3.6", release:"CentOS-2", cpu:"i386") )  faulty += '- php-pgsql-4.3.9-3.6\n';
if ( rpm_check(reference:"php-domxml-4.3.9-3.6", release:"CentOS-2", cpu:"i386") )  faulty += '- php-domxml-4.3.9-3.6\n';
if ( rpm_check(reference:"php-mysql-4.3.9-3.6", release:"CentOS-2", cpu:"i386") )  faulty += '- php-mysql-4.3.9-3.6\n';
if ( rpm_check(reference:"php-snmp-4.3.9-3.6", release:"CentOS-2", cpu:"i386") )  faulty += '- php-snmp-4.3.9-3.6\n';
if ( rpm_check(reference:"php-gd-4.3.9-3.6", release:"CentOS-2", cpu:"i386") )  faulty += '- php-gd-4.3.9-3.6\n';
if ( rpm_check(reference:"php-ncurses-4.3.9-3.6", release:"CentOS-2", cpu:"i386") )  faulty += '- php-ncurses-4.3.9-3.6\n';
if ( rpm_check(reference:"php-xmlrpc-4.3.9-3.6", release:"CentOS-2", cpu:"i386") )  faulty += '- php-xmlrpc-4.3.9-3.6\n';
if ( rpm_check(reference:"php-imap-4.3.9-3.6", release:"CentOS-2", cpu:"i386") )  faulty += '- php-imap-4.3.9-3.6\n';
if ( rpm_check(reference:"php-odbc-4.3.9-3.6", release:"CentOS-2", cpu:"i386") )  faulty += '- php-odbc-4.3.9-3.6\n';
if ( rpm_check(reference:"php-4.3.9-3.6", release:"CentOS-2", cpu:"x86_64") )  faulty += '- php-4.3.9-3.6\n';
if ( rpm_check(reference:"php-devel-4.3.9-3.6", release:"CentOS-2", cpu:"x86_64") )  faulty += '- php-devel-4.3.9-3.6\n';
if ( rpm_check(reference:"php-domxml-4.3.9-3.6", release:"CentOS-2", cpu:"x86_64") )  faulty += '- php-domxml-4.3.9-3.6\n';
if ( rpm_check(reference:"php-gd-4.3.9-3.6", release:"CentOS-2", cpu:"x86_64") )  faulty += '- php-gd-4.3.9-3.6\n';
if ( rpm_check(reference:"php-imap-4.3.9-3.6", release:"CentOS-2", cpu:"x86_64") )  faulty += '- php-imap-4.3.9-3.6\n';
if ( rpm_check(reference:"php-ldap-4.3.9-3.6", release:"CentOS-2", cpu:"x86_64") )  faulty += '- php-ldap-4.3.9-3.6\n';
if ( rpm_check(reference:"php-mbstring-4.3.9-3.6", release:"CentOS-2", cpu:"x86_64") )  faulty += '- php-mbstring-4.3.9-3.6\n';
if ( rpm_check(reference:"php-mysql-4.3.9-3.6", release:"CentOS-2", cpu:"x86_64") )  faulty += '- php-mysql-4.3.9-3.6\n';
if ( rpm_check(reference:"php-ncurses-4.3.9-3.6", release:"CentOS-2", cpu:"x86_64") )  faulty += '- php-ncurses-4.3.9-3.6\n';
if ( rpm_check(reference:"php-odbc-4.3.9-3.6", release:"CentOS-2", cpu:"x86_64") )  faulty += '- php-odbc-4.3.9-3.6\n';
if ( rpm_check(reference:"php-pear-4.3.9-3.6", release:"CentOS-2", cpu:"x86_64") )  faulty += '- php-pear-4.3.9-3.6\n';
if ( rpm_check(reference:"php-pgsql-4.3.9-3.6", release:"CentOS-2", cpu:"x86_64") )  faulty += '- php-pgsql-4.3.9-3.6\n';
if ( rpm_check(reference:"php-snmp-4.3.9-3.6", release:"CentOS-2", cpu:"x86_64") )  faulty += '- php-snmp-4.3.9-3.6\n';
if ( rpm_check(reference:"php-xmlrpc-4.3.9-3.6", release:"CentOS-2", cpu:"x86_64") )  faulty += '- php-xmlrpc-4.3.9-3.6\n';
if ( rpm_check(reference:"evolution-2.0.2-16", release:"CentOS-2", cpu:"i386") )  faulty += '- evolution-2.0.2-16\n';
if ( rpm_check(reference:"evolution-devel-2.0.2-16", release:"CentOS-2", cpu:"i386") )  faulty += '- evolution-devel-2.0.2-16\n';
if ( rpm_check(reference:"evolution-2.0.2-16", release:"CentOS-2", cpu:"x86_64") )  faulty += '- evolution-2.0.2-16\n';
if ( rpm_check(reference:"evolution-devel-2.0.2-16", release:"CentOS-2", cpu:"x86_64") )  faulty += '- evolution-devel-2.0.2-16\n';
if ( rpm_check(reference:"nasm-0.98.38-3.EL4", release:"CentOS-2", cpu:"i386") )  faulty += '- nasm-0.98.38-3.EL4\n';
if ( rpm_check(reference:"nasm-rdoff-0.98.38-3.EL4", release:"CentOS-2", cpu:"i386") )  faulty += '- nasm-rdoff-0.98.38-3.EL4\n';
if ( rpm_check(reference:"nasm-doc-0.98.38-3.EL4", release:"CentOS-2", cpu:"i386") )  faulty += '- nasm-doc-0.98.38-3.EL4\n';
if ( rpm_check(reference:"nasm-0.98.38-3.EL4", release:"CentOS-2", cpu:"x86_64") )  faulty += '- nasm-0.98.38-3.EL4\n';
if ( rpm_check(reference:"nasm-rdoff-0.98.38-3.EL4", release:"CentOS-2", cpu:"x86_64") )  faulty += '- nasm-rdoff-0.98.38-3.EL4\n';
if ( rpm_check(reference:"nasm-doc-0.98.38-3.EL4", release:"CentOS-2", cpu:"x86_64") )  faulty += '- nasm-doc-0.98.38-3.EL4\n';
if ( rpm_check(reference:"nasm-0.98-8.EL21", release:"CentOS-2", cpu:"i386") )  faulty += '- nasm-0.98-8.EL21\n';
if ( rpm_check(reference:"nasm-doc-0.98-8.EL21", release:"CentOS-2", cpu:"i386") )  faulty += '- nasm-doc-0.98-8.EL21\n';
if ( rpm_check(reference:"nasm-rdoff-0.98-8.EL21", release:"CentOS-2", cpu:"i386") )  faulty += '- nasm-rdoff-0.98-8.EL21\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
