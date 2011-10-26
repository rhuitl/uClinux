#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2005-767.

See also :

https://rhn.redhat.com/errata/RHSA-2005-767.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(21961);
 script_version("$Revision: 1.3 $");
 script_name(english:"CentOS : RHSA-2005-767");
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

if ( rpm_check(reference:"compat-openldap-2.1.30-4", release:"CentOS-4", cpu:"ia64") )  faulty += '- compat-openldap-2.1.30-4\n';
if ( rpm_check(reference:"nss_ldap-226-10", release:"CentOS-4", cpu:"ia64") )  faulty += '- nss_ldap-226-10\n';
if ( rpm_check(reference:"openldap-2.2.13-4", release:"CentOS-4", cpu:"ia64") )  faulty += '- openldap-2.2.13-4\n';
if ( rpm_check(reference:"openldap-clients-2.2.13-4", release:"CentOS-4", cpu:"ia64") )  faulty += '- openldap-clients-2.2.13-4\n';
if ( rpm_check(reference:"openldap-devel-2.2.13-4", release:"CentOS-4", cpu:"ia64") )  faulty += '- openldap-devel-2.2.13-4\n';
if ( rpm_check(reference:"openldap-servers-2.2.13-4", release:"CentOS-4", cpu:"ia64") )  faulty += '- openldap-servers-2.2.13-4\n';
if ( rpm_check(reference:"openldap-servers-sql-2.2.13-4", release:"CentOS-4", cpu:"ia64") )  faulty += '- openldap-servers-sql-2.2.13-4\n';
if ( rpm_check(reference:"nss_ldap-189-13", release:"CentOS-4", cpu:"i386") )  faulty += '- nss_ldap-189-13\n';
if ( rpm_check(reference:"openldap-2.0.27-4.9", release:"CentOS-4", cpu:"i386") )  faulty += '- openldap-2.0.27-4.9\n';
if ( rpm_check(reference:"openldap-clients-2.0.27-4.9", release:"CentOS-4", cpu:"i386") )  faulty += '- openldap-clients-2.0.27-4.9\n';
if ( rpm_check(reference:"openldap-devel-2.0.27-4.9", release:"CentOS-4", cpu:"i386") )  faulty += '- openldap-devel-2.0.27-4.9\n';
if ( rpm_check(reference:"openldap-servers-2.0.27-4.9", release:"CentOS-4", cpu:"i386") )  faulty += '- openldap-servers-2.0.27-4.9\n';
if ( rpm_check(reference:"lynx-2.8.4-18.1.1", release:"CentOS-4", cpu:"i386") )  faulty += '- lynx-2.8.4-18.1.1\n';
if ( rpm_check(reference:"compat-openldap-2.1.30-4", release:"CentOS-4", cpu:"i386") )  faulty += '- compat-openldap-2.1.30-4\n';
if ( rpm_check(reference:"nss_ldap-226-10", release:"CentOS-4", cpu:"i386") )  faulty += '- nss_ldap-226-10\n';
if ( rpm_check(reference:"openldap-2.2.13-4", release:"CentOS-4", cpu:"i386") )  faulty += '- openldap-2.2.13-4\n';
if ( rpm_check(reference:"openldap-clients-2.2.13-4", release:"CentOS-4", cpu:"i386") )  faulty += '- openldap-clients-2.2.13-4\n';
if ( rpm_check(reference:"openldap-devel-2.2.13-4", release:"CentOS-4", cpu:"i386") )  faulty += '- openldap-devel-2.2.13-4\n';
if ( rpm_check(reference:"openldap-servers-2.2.13-4", release:"CentOS-4", cpu:"i386") )  faulty += '- openldap-servers-2.2.13-4\n';
if ( rpm_check(reference:"openldap-servers-sql-2.2.13-4", release:"CentOS-4", cpu:"i386") )  faulty += '- openldap-servers-sql-2.2.13-4\n';
if ( rpm_check(reference:"compat-openldap-2.1.30-4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- compat-openldap-2.1.30-4\n';
if ( rpm_check(reference:"nss_ldap-226-10", release:"CentOS-4", cpu:"x86_64") )  faulty += '- nss_ldap-226-10\n';
if ( rpm_check(reference:"openldap-2.2.13-4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- openldap-2.2.13-4\n';
if ( rpm_check(reference:"openldap-clients-2.2.13-4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- openldap-clients-2.2.13-4\n';
if ( rpm_check(reference:"openldap-devel-2.2.13-4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- openldap-devel-2.2.13-4\n';
if ( rpm_check(reference:"openldap-servers-2.2.13-4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- openldap-servers-2.2.13-4\n';
if ( rpm_check(reference:"openldap-servers-sql-2.2.13-4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- openldap-servers-sql-2.2.13-4\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
