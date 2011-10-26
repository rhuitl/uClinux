#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2006-0159.

See also :

https://rhn.redhat.com/errata/RHSA-2006-0159.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(21884);
 script_version("$Revision: 1.4 $");
 script_name(english:"CentOS : RHSA-2006-0159");
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

if ( rpm_check(reference:"httpd-2.0.52-22.ent.centos4", release:"CentOS-4", cpu:"ia64") )  faulty += '- httpd-2.0.52-22.ent.centos4\n';
if ( rpm_check(reference:"httpd-devel-2.0.52-22.ent.centos4", release:"CentOS-4", cpu:"ia64") )  faulty += '- httpd-devel-2.0.52-22.ent.centos4\n';
if ( rpm_check(reference:"httpd-manual-2.0.52-22.ent.centos4", release:"CentOS-4", cpu:"ia64") )  faulty += '- httpd-manual-2.0.52-22.ent.centos4\n';
if ( rpm_check(reference:"httpd-suexec-2.0.52-22.ent.centos4", release:"CentOS-4", cpu:"ia64") )  faulty += '- httpd-suexec-2.0.52-22.ent.centos4\n';
if ( rpm_check(reference:"mod_ssl-2.0.52-22.ent.centos4", release:"CentOS-4", cpu:"ia64") )  faulty += '- mod_ssl-2.0.52-22.ent.centos4\n';
if ( rpm_check(reference:"httpd-2.0.46-56.ent.centos.1", release:"CentOS-3", cpu:"ia64") )  faulty += '- httpd-2.0.46-56.ent.centos.1\n';
if ( rpm_check(reference:"httpd-devel-2.0.46-56.ent.centos.1", release:"CentOS-3", cpu:"ia64") )  faulty += '- httpd-devel-2.0.46-56.ent.centos.1\n';
if ( rpm_check(reference:"mod_ssl-2.0.46-56.ent.centos.1", release:"CentOS-3", cpu:"ia64") )  faulty += '- mod_ssl-2.0.46-56.ent.centos.1\n';
if ( rpm_check(reference:"httpd-2.0.46-56.ent.centos.1", release:"CentOS-3", cpu:"i386") )  faulty += '- httpd-2.0.46-56.ent.centos.1\n';
if ( rpm_check(reference:"httpd-devel-2.0.46-56.ent.centos.1", release:"CentOS-3", cpu:"i386") )  faulty += '- httpd-devel-2.0.46-56.ent.centos.1\n';
if ( rpm_check(reference:"mod_ssl-2.0.46-56.ent.centos.1", release:"CentOS-3", cpu:"i386") )  faulty += '- mod_ssl-2.0.46-56.ent.centos.1\n';
if ( rpm_check(reference:"httpd-2.0.46-56.ent.centos.1", release:"CentOS-3", cpu:"x86_64") )  faulty += '- httpd-2.0.46-56.ent.centos.1\n';
if ( rpm_check(reference:"httpd-devel-2.0.46-56.ent.centos.1", release:"CentOS-3", cpu:"x86_64") )  faulty += '- httpd-devel-2.0.46-56.ent.centos.1\n';
if ( rpm_check(reference:"mod_ssl-2.0.46-56.ent.centos.1", release:"CentOS-3", cpu:"x86_64") )  faulty += '- mod_ssl-2.0.46-56.ent.centos.1\n';
if ( rpm_check(reference:"httpd-2.0.52-22.ent.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- httpd-2.0.52-22.ent.centos4\n';
if ( rpm_check(reference:"httpd-devel-2.0.52-22.ent.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- httpd-devel-2.0.52-22.ent.centos4\n';
if ( rpm_check(reference:"httpd-manual-2.0.52-22.ent.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- httpd-manual-2.0.52-22.ent.centos4\n';
if ( rpm_check(reference:"httpd-suexec-2.0.52-22.ent.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- httpd-suexec-2.0.52-22.ent.centos4\n';
if ( rpm_check(reference:"mod_ssl-2.0.52-22.ent.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- mod_ssl-2.0.52-22.ent.centos4\n';
if ( rpm_check(reference:"httpd-2.0.52-22.ent.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- httpd-2.0.52-22.ent.centos4\n';
if ( rpm_check(reference:"httpd-devel-2.0.52-22.ent.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- httpd-devel-2.0.52-22.ent.centos4\n';
if ( rpm_check(reference:"httpd-manual-2.0.52-22.ent.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- httpd-manual-2.0.52-22.ent.centos4\n';
if ( rpm_check(reference:"httpd-suexec-2.0.52-22.ent.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- httpd-suexec-2.0.52-22.ent.centos4\n';
if ( rpm_check(reference:"mod_ssl-2.0.52-22.ent.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- mod_ssl-2.0.52-22.ent.centos4\n';
if ( rpm_check(reference:"apache-1.3.27-10.ent.c2.1", release:"CentOS-4", cpu:"i386") )  faulty += '- apache-1.3.27-10.ent.c2.1\n';
if ( rpm_check(reference:"apache-devel-1.3.27-10.ent.c2.1", release:"CentOS-4", cpu:"i386") )  faulty += '- apache-devel-1.3.27-10.ent.c2.1\n';
if ( rpm_check(reference:"apache-manual-1.3.27-10.ent.c2.1", release:"CentOS-4", cpu:"i386") )  faulty += '- apache-manual-1.3.27-10.ent.c2.1\n';
if ( rpm_check(reference:"tetex-1.0.7-38.5E.10", release:"CentOS-4", cpu:"i386") )  faulty += '- tetex-1.0.7-38.5E.10\n';
if ( rpm_check(reference:"tetex-afm-1.0.7-38.5E.10", release:"CentOS-4", cpu:"i386") )  faulty += '- tetex-afm-1.0.7-38.5E.10\n';
if ( rpm_check(reference:"tetex-doc-1.0.7-38.5E.10", release:"CentOS-4", cpu:"i386") )  faulty += '- tetex-doc-1.0.7-38.5E.10\n';
if ( rpm_check(reference:"tetex-dvilj-1.0.7-38.5E.10", release:"CentOS-4", cpu:"i386") )  faulty += '- tetex-dvilj-1.0.7-38.5E.10\n';
if ( rpm_check(reference:"tetex-dvips-1.0.7-38.5E.10", release:"CentOS-4", cpu:"i386") )  faulty += '- tetex-dvips-1.0.7-38.5E.10\n';
if ( rpm_check(reference:"tetex-fonts-1.0.7-38.5E.10", release:"CentOS-4", cpu:"i386") )  faulty += '- tetex-fonts-1.0.7-38.5E.10\n';
if ( rpm_check(reference:"tetex-latex-1.0.7-38.5E.10", release:"CentOS-4", cpu:"i386") )  faulty += '- tetex-latex-1.0.7-38.5E.10\n';
if ( rpm_check(reference:"tetex-xdvi-1.0.7-38.5E.10", release:"CentOS-4", cpu:"i386") )  faulty += '- tetex-xdvi-1.0.7-38.5E.10\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
