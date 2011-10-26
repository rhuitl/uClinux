#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2005-659.

See also :

https://rhn.redhat.com/errata/RHSA-2005-659.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(21848);
 script_version("$Revision: 1.4 $");
 script_name(english:"CentOS : RHSA-2005-659");
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

if ( rpm_check(reference:"cups-libs-1.1.22-0.rc1.9.8", release:"CentOS-3", cpu:"i386") )  faulty += '- cups-libs-1.1.22-0.rc1.9.8\n';
if ( rpm_check(reference:"cups-devel-1.1.22-0.rc1.9.8", release:"CentOS-3", cpu:"i386") )  faulty += '- cups-devel-1.1.22-0.rc1.9.8\n';
if ( rpm_check(reference:"cups-1.1.22-0.rc1.9.8", release:"CentOS-3", cpu:"i386") )  faulty += '- cups-1.1.22-0.rc1.9.8\n';
if ( rpm_check(reference:"cups-1.1.22-0.rc1.9.8", release:"CentOS-3", cpu:"x86_64") )  faulty += '- cups-1.1.22-0.rc1.9.8\n';
if ( rpm_check(reference:"cups-devel-1.1.22-0.rc1.9.8", release:"CentOS-3", cpu:"x86_64") )  faulty += '- cups-devel-1.1.22-0.rc1.9.8\n';
if ( rpm_check(reference:"cups-libs-1.1.22-0.rc1.9.8", release:"CentOS-3", cpu:"x86_64") )  faulty += '- cups-libs-1.1.22-0.rc1.9.8\n';
if ( rpm_check(reference:"HelixPlayer-1.0.6-0.EL4.1", release:"CentOS-3", cpu:"i386") )  faulty += '- HelixPlayer-1.0.6-0.EL4.1\n';
if ( rpm_check(reference:"wget-1.10.1-2.4E.1", release:"CentOS-3", cpu:"i386") )  faulty += '- wget-1.10.1-2.4E.1\n';
if ( rpm_check(reference:"wget-1.10.1-2.4E.1", release:"CentOS-3", cpu:"x86_64") )  faulty += '- wget-1.10.1-2.4E.1\n';
if ( rpm_check(reference:"wget-1.10.1-0.AS21", release:"CentOS-3", cpu:"i386") )  faulty += '- wget-1.10.1-0.AS21\n';
if ( rpm_check(reference:"binutils-2.14.90.0.4-39", release:"CentOS-3", cpu:"ia64") )  faulty += '- binutils-2.14.90.0.4-39\n';
if ( rpm_check(reference:"binutils-2.14.90.0.4-39", release:"CentOS-3", cpu:"i386") )  faulty += '- binutils-2.14.90.0.4-39\n';
if ( rpm_check(reference:"binutils-2.14.90.0.4-39", release:"CentOS-3", cpu:"x86_64") )  faulty += '- binutils-2.14.90.0.4-39\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
