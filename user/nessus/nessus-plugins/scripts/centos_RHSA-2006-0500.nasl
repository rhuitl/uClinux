#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2006-0500.

See also :

https://rhn.redhat.com/errata/RHSA-2006-0500.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(22064);
 script_version("$Revision: 1.3 $");
 script_name(english:"CentOS : RHSA-2006-0500");
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

if ( rpm_check(reference:"kernel-BOOT-2.4.9-e.70", release:"CentOS-4", cpu:"i386") )  faulty += '- kernel-BOOT-2.4.9-e.70\n';
if ( rpm_check(reference:"kernel-doc-2.4.9-e.70", release:"CentOS-4", cpu:"i386") )  faulty += '- kernel-doc-2.4.9-e.70\n';
if ( rpm_check(reference:"kernel-headers-2.4.9-e.70", release:"CentOS-4", cpu:"i386") )  faulty += '- kernel-headers-2.4.9-e.70\n';
if ( rpm_check(reference:"kernel-source-2.4.9-e.70", release:"CentOS-4", cpu:"i386") )  faulty += '- kernel-source-2.4.9-e.70\n';
if ( rpm_check(reference:"kernel-2.4.9-e.70", release:"CentOS-4", cpu:"i686") )  faulty += '- kernel-2.4.9-e.70\n';
if ( rpm_check(reference:"kernel-debug-2.4.9-e.70", release:"CentOS-4", cpu:"i686") )  faulty += '- kernel-debug-2.4.9-e.70\n';
if ( rpm_check(reference:"kernel-enterprise-2.4.9-e.70", release:"CentOS-4", cpu:"i686") )  faulty += '- kernel-enterprise-2.4.9-e.70\n';
if ( rpm_check(reference:"kernel-smp-2.4.9-e.70", release:"CentOS-4", cpu:"i686") )  faulty += '- kernel-smp-2.4.9-e.70\n';
if ( rpm_check(reference:"kernel-summit-2.4.9-e.70", release:"CentOS-4", cpu:"i686") )  faulty += '- kernel-summit-2.4.9-e.70\n';
if ( rpm_check(reference:"kernel-2.4.9-e.70", release:"CentOS-4", cpu:"athlon") )  faulty += '- kernel-2.4.9-e.70\n';
if ( rpm_check(reference:"kernel-smp-2.4.9-e.70", release:"CentOS-4", cpu:"athlon") )  faulty += '- kernel-smp-2.4.9-e.70\n';
if ( rpm_check(reference:"freetype-2.1.9-1.rhel4.4", release:"CentOS-4", cpu:"ia64") )  faulty += '- freetype-2.1.9-1.rhel4.4\n';
if ( rpm_check(reference:"freetype-demos-2.1.9-1.rhel4.4", release:"CentOS-4", cpu:"ia64") )  faulty += '- freetype-demos-2.1.9-1.rhel4.4\n';
if ( rpm_check(reference:"freetype-devel-2.1.9-1.rhel4.4", release:"CentOS-4", cpu:"ia64") )  faulty += '- freetype-devel-2.1.9-1.rhel4.4\n';
if ( rpm_check(reference:"freetype-utils-2.1.9-1.rhel4.4", release:"CentOS-4", cpu:"ia64") )  faulty += '- freetype-utils-2.1.9-1.rhel4.4\n';
if ( rpm_check(reference:"freetype-2.1.4-4.0.rhel3.2", release:"CentOS-3", cpu:"ia64") )  faulty += '- freetype-2.1.4-4.0.rhel3.2\n';
if ( rpm_check(reference:"freetype-demos-2.1.4-4.0.rhel3.2", release:"CentOS-3", cpu:"ia64") )  faulty += '- freetype-demos-2.1.4-4.0.rhel3.2\n';
if ( rpm_check(reference:"freetype-devel-2.1.4-4.0.rhel3.2", release:"CentOS-3", cpu:"ia64") )  faulty += '- freetype-devel-2.1.4-4.0.rhel3.2\n';
if ( rpm_check(reference:"freetype-utils-2.1.4-4.0.rhel3.2", release:"CentOS-3", cpu:"ia64") )  faulty += '- freetype-utils-2.1.4-4.0.rhel3.2\n';
if ( rpm_check(reference:"freetype-2.1.9-1.rhel4.4", release:"CentOS-4", cpu:"i386") )  faulty += '- freetype-2.1.9-1.rhel4.4\n';
if ( rpm_check(reference:"freetype-2.1.9-1.rhel4.4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- freetype-2.1.9-1.rhel4.4\n';
if ( rpm_check(reference:"freetype-demos-2.1.9-1.rhel4.4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- freetype-demos-2.1.9-1.rhel4.4\n';
if ( rpm_check(reference:"freetype-devel-2.1.9-1.rhel4.4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- freetype-devel-2.1.9-1.rhel4.4\n';
if ( rpm_check(reference:"freetype-utils-2.1.9-1.rhel4.4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- freetype-utils-2.1.9-1.rhel4.4\n';
if ( rpm_check(reference:"freetype-demos-2.1.9-1.rhel4.4", release:"CentOS-4", cpu:"i386") )  faulty += '- freetype-demos-2.1.9-1.rhel4.4\n';
if ( rpm_check(reference:"freetype-devel-2.1.9-1.rhel4.4", release:"CentOS-4", cpu:"i386") )  faulty += '- freetype-devel-2.1.9-1.rhel4.4\n';
if ( rpm_check(reference:"freetype-utils-2.1.9-1.rhel4.4", release:"CentOS-4", cpu:"i386") )  faulty += '- freetype-utils-2.1.9-1.rhel4.4\n';
if ( rpm_check(reference:"freetype-2.1.4-4.0.rhel3.2", release:"CentOS-3", cpu:"i386") )  faulty += '- freetype-2.1.4-4.0.rhel3.2\n';
if ( rpm_check(reference:"freetype-2.1.4-4.0.rhel3.2", release:"CentOS-3", cpu:"x86_64") )  faulty += '- freetype-2.1.4-4.0.rhel3.2\n';
if ( rpm_check(reference:"freetype-devel-2.1.4-4.0.rhel3.2", release:"CentOS-3", cpu:"i386") )  faulty += '- freetype-devel-2.1.4-4.0.rhel3.2\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
