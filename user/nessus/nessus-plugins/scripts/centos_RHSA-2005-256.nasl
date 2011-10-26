#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2005-256.

See also :

https://rhn.redhat.com/errata/RHSA-2005-256.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(21800);
 script_version("$Revision: 1.4 $");
 script_name(english:"CentOS : RHSA-2005-256");
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

if ( rpm_check(reference:"glibc-2.3.2-95.33", release:"CentOS-3", cpu:"ia64") )  faulty += '- glibc-2.3.2-95.33\n';
if ( rpm_check(reference:"glibc-common-2.3.2-95.33", release:"CentOS-3", cpu:"ia64") )  faulty += '- glibc-common-2.3.2-95.33\n';
if ( rpm_check(reference:"glibc-debug-2.3.2-95.33", release:"CentOS-3", cpu:"ia64") )  faulty += '- glibc-debug-2.3.2-95.33\n';
if ( rpm_check(reference:"glibc-devel-2.3.2-95.33", release:"CentOS-3", cpu:"ia64") )  faulty += '- glibc-devel-2.3.2-95.33\n';
if ( rpm_check(reference:"glibc-headers-2.3.2-95.33", release:"CentOS-3", cpu:"ia64") )  faulty += '- glibc-headers-2.3.2-95.33\n';
if ( rpm_check(reference:"glibc-profile-2.3.2-95.33", release:"CentOS-3", cpu:"ia64") )  faulty += '- glibc-profile-2.3.2-95.33\n';
if ( rpm_check(reference:"glibc-utils-2.3.2-95.33", release:"CentOS-3", cpu:"ia64") )  faulty += '- glibc-utils-2.3.2-95.33\n';
if ( rpm_check(reference:"nptl-devel-2.3.2-95.33", release:"CentOS-3", cpu:"ia64") )  faulty += '- nptl-devel-2.3.2-95.33\n';
if ( rpm_check(reference:"nscd-2.3.2-95.33", release:"CentOS-3", cpu:"ia64") )  faulty += '- nscd-2.3.2-95.33\n';
if ( rpm_check(reference:"glibc-2.3.2-95.33", release:"CentOS-3", cpu:"i386") )  faulty += '- glibc-2.3.2-95.33\n';
if ( rpm_check(reference:"glibc-2.3.2-95.33", release:"CentOS-3", cpu:"i686") )  faulty += '- glibc-2.3.2-95.33\n';
if ( rpm_check(reference:"glibc-common-2.3.2-95.33", release:"CentOS-3", cpu:"i386") )  faulty += '- glibc-common-2.3.2-95.33\n';
if ( rpm_check(reference:"glibc-debug-2.3.2-95.33", release:"CentOS-3", cpu:"i386") )  faulty += '- glibc-debug-2.3.2-95.33\n';
if ( rpm_check(reference:"glibc-devel-2.3.2-95.33", release:"CentOS-3", cpu:"i386") )  faulty += '- glibc-devel-2.3.2-95.33\n';
if ( rpm_check(reference:"glibc-headers-2.3.2-95.33", release:"CentOS-3", cpu:"i386") )  faulty += '- glibc-headers-2.3.2-95.33\n';
if ( rpm_check(reference:"glibc-profile-2.3.2-95.33", release:"CentOS-3", cpu:"i386") )  faulty += '- glibc-profile-2.3.2-95.33\n';
if ( rpm_check(reference:"glibc-utils-2.3.2-95.33", release:"CentOS-3", cpu:"i386") )  faulty += '- glibc-utils-2.3.2-95.33\n';
if ( rpm_check(reference:"nptl-devel-2.3.2-95.33", release:"CentOS-3", cpu:"i686") )  faulty += '- nptl-devel-2.3.2-95.33\n';
if ( rpm_check(reference:"nscd-2.3.2-95.33", release:"CentOS-3", cpu:"i386") )  faulty += '- nscd-2.3.2-95.33\n';
if ( rpm_check(reference:"glibc-2.3.2-95.33", release:"CentOS-3", cpu:"x86_64") )  faulty += '- glibc-2.3.2-95.33\n';
if ( rpm_check(reference:"glibc-common-2.3.2-95.33", release:"CentOS-3", cpu:"x86_64") )  faulty += '- glibc-common-2.3.2-95.33\n';
if ( rpm_check(reference:"glibc-debug-2.3.2-95.33", release:"CentOS-3", cpu:"x86_64") )  faulty += '- glibc-debug-2.3.2-95.33\n';
if ( rpm_check(reference:"glibc-devel-2.3.2-95.33", release:"CentOS-3", cpu:"x86_64") )  faulty += '- glibc-devel-2.3.2-95.33\n';
if ( rpm_check(reference:"glibc-headers-2.3.2-95.33", release:"CentOS-3", cpu:"x86_64") )  faulty += '- glibc-headers-2.3.2-95.33\n';
if ( rpm_check(reference:"glibc-profile-2.3.2-95.33", release:"CentOS-3", cpu:"x86_64") )  faulty += '- glibc-profile-2.3.2-95.33\n';
if ( rpm_check(reference:"glibc-utils-2.3.2-95.33", release:"CentOS-3", cpu:"x86_64") )  faulty += '- glibc-utils-2.3.2-95.33\n';
if ( rpm_check(reference:"nptl-devel-2.3.2-95.33", release:"CentOS-3", cpu:"x86_64") )  faulty += '- nptl-devel-2.3.2-95.33\n';
if ( rpm_check(reference:"nscd-2.3.2-95.33", release:"CentOS-3", cpu:"x86_64") )  faulty += '- nscd-2.3.2-95.33\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
