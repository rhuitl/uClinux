#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2005-608.

See also :

https://rhn.redhat.com/errata/RHSA-2005-608.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(21845);
 script_version("$Revision: 1.4 $");
 script_name(english:"CentOS : RHSA-2005-608");
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

if ( rpm_check(reference:"httpd-2.0.46-46.3.ent.centos.1", release:"CentOS-3", cpu:"i386") )  faulty += '- httpd-2.0.46-46.3.ent.centos.1\n';
if ( rpm_check(reference:"httpd-devel-2.0.46-46.3.ent.centos.1", release:"CentOS-3", cpu:"i386") )  faulty += '- httpd-devel-2.0.46-46.3.ent.centos.1\n';
if ( rpm_check(reference:"mod_ssl-2.0.46-46.3.ent.centos.1", release:"CentOS-3", cpu:"i386") )  faulty += '- mod_ssl-2.0.46-46.3.ent.centos.1\n';
if ( rpm_check(reference:"httpd-2.0.46-46.3.ent.centos.1", release:"CentOS-3", cpu:"x86_64") )  faulty += '- httpd-2.0.46-46.3.ent.centos.1\n';
if ( rpm_check(reference:"httpd-devel-2.0.46-46.3.ent.centos.1", release:"CentOS-3", cpu:"x86_64") )  faulty += '- httpd-devel-2.0.46-46.3.ent.centos.1\n';
if ( rpm_check(reference:"mod_ssl-2.0.46-46.3.ent.centos.1", release:"CentOS-3", cpu:"x86_64") )  faulty += '- mod_ssl-2.0.46-46.3.ent.centos.1\n';
if ( rpm_check(reference:"httpd-2.0.52-12.2.ent.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- httpd-2.0.52-12.2.ent.centos4\n';
if ( rpm_check(reference:"httpd-devel-2.0.52-12.2.ent.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- httpd-devel-2.0.52-12.2.ent.centos4\n';
if ( rpm_check(reference:"httpd-manual-2.0.52-12.2.ent.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- httpd-manual-2.0.52-12.2.ent.centos4\n';
if ( rpm_check(reference:"httpd-suexec-2.0.52-12.2.ent.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- httpd-suexec-2.0.52-12.2.ent.centos4\n';
if ( rpm_check(reference:"mod_ssl-2.0.52-12.2.ent.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- mod_ssl-2.0.52-12.2.ent.centos4\n';
if ( rpm_check(reference:"httpd-2.0.52-12.2.ent.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- httpd-2.0.52-12.2.ent.centos4\n';
if ( rpm_check(reference:"httpd-devel-2.0.52-12.2.ent.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- httpd-devel-2.0.52-12.2.ent.centos4\n';
if ( rpm_check(reference:"httpd-manual-2.0.52-12.2.ent.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- httpd-manual-2.0.52-12.2.ent.centos4\n';
if ( rpm_check(reference:"httpd-suexec-2.0.52-12.2.ent.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- httpd-suexec-2.0.52-12.2.ent.centos4\n';
if ( rpm_check(reference:"mod_ssl-2.0.52-12.2.ent.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- mod_ssl-2.0.52-12.2.ent.centos4\n';
if ( rpm_check(reference:"httpd-2.0.52-12.2.ent.centos4", release:"CentOS-4", cpu:"ia64") )  faulty += '- httpd-2.0.52-12.2.ent.centos4\n';
if ( rpm_check(reference:"httpd-devel-2.0.52-12.2.ent.centos4", release:"CentOS-4", cpu:"ia64") )  faulty += '- httpd-devel-2.0.52-12.2.ent.centos4\n';
if ( rpm_check(reference:"httpd-manual-2.0.52-12.2.ent.centos4", release:"CentOS-4", cpu:"ia64") )  faulty += '- httpd-manual-2.0.52-12.2.ent.centos4\n';
if ( rpm_check(reference:"httpd-suexec-2.0.52-12.2.ent.centos4", release:"CentOS-4", cpu:"ia64") )  faulty += '- httpd-suexec-2.0.52-12.2.ent.centos4\n';
if ( rpm_check(reference:"mod_ssl-2.0.52-12.2.ent.centos4", release:"CentOS-4", cpu:"ia64") )  faulty += '- mod_ssl-2.0.52-12.2.ent.centos4\n';
if ( rpm_check(reference:"httpd-2.0.46-46.3.ent.centos.1", release:"CentOS-3", cpu:"ia64") )  faulty += '- httpd-2.0.46-46.3.ent.centos.1\n';
if ( rpm_check(reference:"httpd-devel-2.0.46-46.3.ent.centos.1", release:"CentOS-3", cpu:"ia64") )  faulty += '- httpd-devel-2.0.46-46.3.ent.centos.1\n';
if ( rpm_check(reference:"mod_ssl-2.0.46-46.3.ent.centos.1", release:"CentOS-3", cpu:"ia64") )  faulty += '- mod_ssl-2.0.46-46.3.ent.centos.1\n';
if ( rpm_check(reference:"cvs-1.11.1p1-19", release:"CentOS-3", cpu:"i386") )  faulty += '- cvs-1.11.1p1-19\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
