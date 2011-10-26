#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2005-375.

See also :

https://rhn.redhat.com/errata/RHSA-2005-375.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(21813);
 script_version("$Revision: 1.4 $");
 script_name(english:"CentOS : RHSA-2005-375");
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

if ( rpm_check(reference:"openoffice.org-1.1.2-24.6.0.EL4", release:"CentOS-4", cpu:"i386") )  faulty += '- openoffice.org-1.1.2-24.6.0.EL4\n';
if ( rpm_check(reference:"openoffice.org-kde-1.1.2-24.6.0.EL4", release:"CentOS-4", cpu:"i386") )  faulty += '- openoffice.org-kde-1.1.2-24.6.0.EL4\n';
if ( rpm_check(reference:"openoffice.org-i18n-1.1.2-24.6.0.EL4", release:"CentOS-4", cpu:"i386") )  faulty += '- openoffice.org-i18n-1.1.2-24.6.0.EL4\n';
if ( rpm_check(reference:"openoffice.org-libs-1.1.2-24.6.0.EL4", release:"CentOS-4", cpu:"i386") )  faulty += '- openoffice.org-libs-1.1.2-24.6.0.EL4\n';
if ( rpm_check(reference:"sharutils-4.2.1-8.9.x", release:"CentOS-3", cpu:"i386") )  faulty += '- sharutils-4.2.1-8.9.x\n';
if ( rpm_check(reference:"cvs-1.11.2-27", release:"CentOS-3", cpu:"i386") )  faulty += '- cvs-1.11.2-27\n';
if ( rpm_check(reference:"openoffice.org-1.1.2-24.2.0.EL3", release:"CentOS-3", cpu:"i386") )  faulty += '- openoffice.org-1.1.2-24.2.0.EL3\n';
if ( rpm_check(reference:"openoffice.org-i18n-1.1.2-24.2.0.EL3", release:"CentOS-3", cpu:"i386") )  faulty += '- openoffice.org-i18n-1.1.2-24.2.0.EL3\n';
if ( rpm_check(reference:"openoffice.org-libs-1.1.2-24.2.0.EL3", release:"CentOS-3", cpu:"i386") )  faulty += '- openoffice.org-libs-1.1.2-24.2.0.EL3\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
