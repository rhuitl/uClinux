#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2005-748.

See also :

https://rhn.redhat.com/errata/RHSA-2005-748.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(21960);
 script_version("$Revision: 1.3 $");
 script_name(english:"CentOS : RHSA-2005-748");
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

if ( rpm_check(reference:"php-4.3.2-25.ent", release:"CentOS-3", cpu:"ia64") )  faulty += '- php-4.3.2-25.ent\n';
if ( rpm_check(reference:"php-devel-4.3.2-25.ent", release:"CentOS-3", cpu:"ia64") )  faulty += '- php-devel-4.3.2-25.ent\n';
if ( rpm_check(reference:"php-imap-4.3.2-25.ent", release:"CentOS-3", cpu:"ia64") )  faulty += '- php-imap-4.3.2-25.ent\n';
if ( rpm_check(reference:"php-ldap-4.3.2-25.ent", release:"CentOS-3", cpu:"ia64") )  faulty += '- php-ldap-4.3.2-25.ent\n';
if ( rpm_check(reference:"php-mysql-4.3.2-25.ent", release:"CentOS-3", cpu:"ia64") )  faulty += '- php-mysql-4.3.2-25.ent\n';
if ( rpm_check(reference:"php-odbc-4.3.2-25.ent", release:"CentOS-3", cpu:"ia64") )  faulty += '- php-odbc-4.3.2-25.ent\n';
if ( rpm_check(reference:"php-pgsql-4.3.2-25.ent", release:"CentOS-3", cpu:"ia64") )  faulty += '- php-pgsql-4.3.2-25.ent\n';
if ( rpm_check(reference:"php-4.3.9-3.8", release:"CentOS-4", cpu:"ia64") )  faulty += '- php-4.3.9-3.8\n';
if ( rpm_check(reference:"php-devel-4.3.9-3.8", release:"CentOS-4", cpu:"ia64") )  faulty += '- php-devel-4.3.9-3.8\n';
if ( rpm_check(reference:"php-domxml-4.3.9-3.8", release:"CentOS-4", cpu:"ia64") )  faulty += '- php-domxml-4.3.9-3.8\n';
if ( rpm_check(reference:"php-gd-4.3.9-3.8", release:"CentOS-4", cpu:"ia64") )  faulty += '- php-gd-4.3.9-3.8\n';
if ( rpm_check(reference:"php-imap-4.3.9-3.8", release:"CentOS-4", cpu:"ia64") )  faulty += '- php-imap-4.3.9-3.8\n';
if ( rpm_check(reference:"php-ldap-4.3.9-3.8", release:"CentOS-4", cpu:"ia64") )  faulty += '- php-ldap-4.3.9-3.8\n';
if ( rpm_check(reference:"php-mbstring-4.3.9-3.8", release:"CentOS-4", cpu:"ia64") )  faulty += '- php-mbstring-4.3.9-3.8\n';
if ( rpm_check(reference:"php-mysql-4.3.9-3.8", release:"CentOS-4", cpu:"ia64") )  faulty += '- php-mysql-4.3.9-3.8\n';
if ( rpm_check(reference:"php-ncurses-4.3.9-3.8", release:"CentOS-4", cpu:"ia64") )  faulty += '- php-ncurses-4.3.9-3.8\n';
if ( rpm_check(reference:"php-odbc-4.3.9-3.8", release:"CentOS-4", cpu:"ia64") )  faulty += '- php-odbc-4.3.9-3.8\n';
if ( rpm_check(reference:"php-pear-4.3.9-3.8", release:"CentOS-4", cpu:"ia64") )  faulty += '- php-pear-4.3.9-3.8\n';
if ( rpm_check(reference:"php-pgsql-4.3.9-3.8", release:"CentOS-4", cpu:"ia64") )  faulty += '- php-pgsql-4.3.9-3.8\n';
if ( rpm_check(reference:"php-snmp-4.3.9-3.8", release:"CentOS-4", cpu:"ia64") )  faulty += '- php-snmp-4.3.9-3.8\n';
if ( rpm_check(reference:"php-xmlrpc-4.3.9-3.8", release:"CentOS-4", cpu:"ia64") )  faulty += '- php-xmlrpc-4.3.9-3.8\n';
if ( rpm_check(reference:"php-4.3.2-25.ent", release:"CentOS-3", cpu:"x86_64") )  faulty += '- php-4.3.2-25.ent\n';
if ( rpm_check(reference:"php-devel-4.3.2-25.ent", release:"CentOS-3", cpu:"x86_64") )  faulty += '- php-devel-4.3.2-25.ent\n';
if ( rpm_check(reference:"php-imap-4.3.2-25.ent", release:"CentOS-3", cpu:"x86_64") )  faulty += '- php-imap-4.3.2-25.ent\n';
if ( rpm_check(reference:"php-ldap-4.3.2-25.ent", release:"CentOS-3", cpu:"x86_64") )  faulty += '- php-ldap-4.3.2-25.ent\n';
if ( rpm_check(reference:"php-mysql-4.3.2-25.ent", release:"CentOS-3", cpu:"x86_64") )  faulty += '- php-mysql-4.3.2-25.ent\n';
if ( rpm_check(reference:"php-odbc-4.3.2-25.ent", release:"CentOS-3", cpu:"x86_64") )  faulty += '- php-odbc-4.3.2-25.ent\n';
if ( rpm_check(reference:"php-pgsql-4.3.2-25.ent", release:"CentOS-3", cpu:"x86_64") )  faulty += '- php-pgsql-4.3.2-25.ent\n';
if ( rpm_check(reference:"php-4.3.2-25.ent", release:"CentOS-3", cpu:"i386") )  faulty += '- php-4.3.2-25.ent\n';
if ( rpm_check(reference:"php-devel-4.3.2-25.ent", release:"CentOS-3", cpu:"i386") )  faulty += '- php-devel-4.3.2-25.ent\n';
if ( rpm_check(reference:"php-imap-4.3.2-25.ent", release:"CentOS-3", cpu:"i386") )  faulty += '- php-imap-4.3.2-25.ent\n';
if ( rpm_check(reference:"php-ldap-4.3.2-25.ent", release:"CentOS-3", cpu:"i386") )  faulty += '- php-ldap-4.3.2-25.ent\n';
if ( rpm_check(reference:"php-mysql-4.3.2-25.ent", release:"CentOS-3", cpu:"i386") )  faulty += '- php-mysql-4.3.2-25.ent\n';
if ( rpm_check(reference:"php-odbc-4.3.2-25.ent", release:"CentOS-3", cpu:"i386") )  faulty += '- php-odbc-4.3.2-25.ent\n';
if ( rpm_check(reference:"php-pgsql-4.3.2-25.ent", release:"CentOS-3", cpu:"i386") )  faulty += '- php-pgsql-4.3.2-25.ent\n';
if ( rpm_check(reference:"php-4.3.9-3.8", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-4.3.9-3.8\n';
if ( rpm_check(reference:"php-devel-4.3.9-3.8", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-devel-4.3.9-3.8\n';
if ( rpm_check(reference:"php-domxml-4.3.9-3.8", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-domxml-4.3.9-3.8\n';
if ( rpm_check(reference:"php-gd-4.3.9-3.8", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-gd-4.3.9-3.8\n';
if ( rpm_check(reference:"php-imap-4.3.9-3.8", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-imap-4.3.9-3.8\n';
if ( rpm_check(reference:"php-ldap-4.3.9-3.8", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-ldap-4.3.9-3.8\n';
if ( rpm_check(reference:"php-mbstring-4.3.9-3.8", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-mbstring-4.3.9-3.8\n';
if ( rpm_check(reference:"php-mysql-4.3.9-3.8", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-mysql-4.3.9-3.8\n';
if ( rpm_check(reference:"php-ncurses-4.3.9-3.8", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-ncurses-4.3.9-3.8\n';
if ( rpm_check(reference:"php-odbc-4.3.9-3.8", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-odbc-4.3.9-3.8\n';
if ( rpm_check(reference:"php-pear-4.3.9-3.8", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-pear-4.3.9-3.8\n';
if ( rpm_check(reference:"php-pgsql-4.3.9-3.8", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-pgsql-4.3.9-3.8\n';
if ( rpm_check(reference:"php-snmp-4.3.9-3.8", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-snmp-4.3.9-3.8\n';
if ( rpm_check(reference:"php-xmlrpc-4.3.9-3.8", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-xmlrpc-4.3.9-3.8\n';
if ( rpm_check(reference:"php-4.3.9-3.8", release:"CentOS-4", cpu:"i386") )  faulty += '- php-4.3.9-3.8\n';
if ( rpm_check(reference:"php-devel-4.3.9-3.8", release:"CentOS-4", cpu:"i386") )  faulty += '- php-devel-4.3.9-3.8\n';
if ( rpm_check(reference:"php-domxml-4.3.9-3.8", release:"CentOS-4", cpu:"i386") )  faulty += '- php-domxml-4.3.9-3.8\n';
if ( rpm_check(reference:"php-gd-4.3.9-3.8", release:"CentOS-4", cpu:"i386") )  faulty += '- php-gd-4.3.9-3.8\n';
if ( rpm_check(reference:"php-imap-4.3.9-3.8", release:"CentOS-4", cpu:"i386") )  faulty += '- php-imap-4.3.9-3.8\n';
if ( rpm_check(reference:"php-ldap-4.3.9-3.8", release:"CentOS-4", cpu:"i386") )  faulty += '- php-ldap-4.3.9-3.8\n';
if ( rpm_check(reference:"php-mbstring-4.3.9-3.8", release:"CentOS-4", cpu:"i386") )  faulty += '- php-mbstring-4.3.9-3.8\n';
if ( rpm_check(reference:"php-mysql-4.3.9-3.8", release:"CentOS-4", cpu:"i386") )  faulty += '- php-mysql-4.3.9-3.8\n';
if ( rpm_check(reference:"php-ncurses-4.3.9-3.8", release:"CentOS-4", cpu:"i386") )  faulty += '- php-ncurses-4.3.9-3.8\n';
if ( rpm_check(reference:"php-odbc-4.3.9-3.8", release:"CentOS-4", cpu:"i386") )  faulty += '- php-odbc-4.3.9-3.8\n';
if ( rpm_check(reference:"php-pear-4.3.9-3.8", release:"CentOS-4", cpu:"i386") )  faulty += '- php-pear-4.3.9-3.8\n';
if ( rpm_check(reference:"php-pgsql-4.3.9-3.8", release:"CentOS-4", cpu:"i386") )  faulty += '- php-pgsql-4.3.9-3.8\n';
if ( rpm_check(reference:"php-snmp-4.3.9-3.8", release:"CentOS-4", cpu:"i386") )  faulty += '- php-snmp-4.3.9-3.8\n';
if ( rpm_check(reference:"php-xmlrpc-4.3.9-3.8", release:"CentOS-4", cpu:"i386") )  faulty += '- php-xmlrpc-4.3.9-3.8\n';
if ( rpm_check(reference:"php-4.3.2-25.ent.centos.1", release:"CentOS-3", cpu:"x86_64") )  faulty += '- php-4.3.2-25.ent.centos.1\n';
if ( rpm_check(reference:"php-devel-4.3.2-25.ent.centos.1", release:"CentOS-3", cpu:"x86_64") )  faulty += '- php-devel-4.3.2-25.ent.centos.1\n';
if ( rpm_check(reference:"php-imap-4.3.2-25.ent.centos.1", release:"CentOS-3", cpu:"x86_64") )  faulty += '- php-imap-4.3.2-25.ent.centos.1\n';
if ( rpm_check(reference:"php-ldap-4.3.2-25.ent.centos.1", release:"CentOS-3", cpu:"x86_64") )  faulty += '- php-ldap-4.3.2-25.ent.centos.1\n';
if ( rpm_check(reference:"php-mysql-4.3.2-25.ent.centos.1", release:"CentOS-3", cpu:"x86_64") )  faulty += '- php-mysql-4.3.2-25.ent.centos.1\n';
if ( rpm_check(reference:"php-odbc-4.3.2-25.ent.centos.1", release:"CentOS-3", cpu:"x86_64") )  faulty += '- php-odbc-4.3.2-25.ent.centos.1\n';
if ( rpm_check(reference:"php-pgsql-4.3.2-25.ent.centos.1", release:"CentOS-3", cpu:"x86_64") )  faulty += '- php-pgsql-4.3.2-25.ent.centos.1\n';
if ( rpm_check(reference:"php-4.3.2-25.ent.centos.1", release:"CentOS-3", cpu:"i386") )  faulty += '- php-4.3.2-25.ent.centos.1\n';
if ( rpm_check(reference:"php-devel-4.3.2-25.ent.centos.1", release:"CentOS-3", cpu:"i386") )  faulty += '- php-devel-4.3.2-25.ent.centos.1\n';
if ( rpm_check(reference:"php-imap-4.3.2-25.ent.centos.1", release:"CentOS-3", cpu:"i386") )  faulty += '- php-imap-4.3.2-25.ent.centos.1\n';
if ( rpm_check(reference:"php-ldap-4.3.2-25.ent.centos.1", release:"CentOS-3", cpu:"i386") )  faulty += '- php-ldap-4.3.2-25.ent.centos.1\n';
if ( rpm_check(reference:"php-mysql-4.3.2-25.ent.centos.1", release:"CentOS-3", cpu:"i386") )  faulty += '- php-mysql-4.3.2-25.ent.centos.1\n';
if ( rpm_check(reference:"php-odbc-4.3.2-25.ent.centos.1", release:"CentOS-3", cpu:"i386") )  faulty += '- php-odbc-4.3.2-25.ent.centos.1\n';
if ( rpm_check(reference:"php-pgsql-4.3.2-25.ent.centos.1", release:"CentOS-3", cpu:"i386") )  faulty += '- php-pgsql-4.3.2-25.ent.centos.1\n';
if ( rpm_check(reference:"php-5.0.4-3.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- php-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-bcmath-5.0.4-3.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- php-bcmath-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-dba-5.0.4-3.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- php-dba-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-devel-5.0.4-3.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- php-devel-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-gd-5.0.4-3.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- php-gd-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-imap-5.0.4-3.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- php-imap-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-ldap-5.0.4-3.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- php-ldap-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-mbstring-5.0.4-3.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- php-mbstring-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-mysql-5.0.4-3.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- php-mysql-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-ncurses-5.0.4-3.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- php-ncurses-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-odbc-5.0.4-3.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- php-odbc-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-pear-5.0.4-3.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- php-pear-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-pgsql-5.0.4-3.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- php-pgsql-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-snmp-5.0.4-3.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- php-snmp-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-soap-5.0.4-3.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- php-soap-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-xml-5.0.4-3.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- php-xml-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-xmlrpc-5.0.4-3.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- php-xmlrpc-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-5.0.4-3.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-bcmath-5.0.4-3.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-bcmath-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-dba-5.0.4-3.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-dba-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-devel-5.0.4-3.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-devel-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-gd-5.0.4-3.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-gd-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-imap-5.0.4-3.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-imap-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-ldap-5.0.4-3.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-ldap-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-mbstring-5.0.4-3.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-mbstring-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-mysql-5.0.4-3.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-mysql-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-ncurses-5.0.4-3.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-ncurses-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-odbc-5.0.4-3.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-odbc-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-pear-5.0.4-3.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-pear-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-pgsql-5.0.4-3.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-pgsql-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-snmp-5.0.4-3.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-snmp-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-soap-5.0.4-3.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-soap-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-xml-5.0.4-3.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-xml-5.0.4-3.centos4\n';
if ( rpm_check(reference:"php-xmlrpc-5.0.4-3.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- php-xmlrpc-5.0.4-3.centos4\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
