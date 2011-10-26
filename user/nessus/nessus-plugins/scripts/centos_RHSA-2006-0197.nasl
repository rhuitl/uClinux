#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2006-0197.

See also :

https://rhn.redhat.com/errata/RHSA-2006-0197.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(21890);
 script_version("$Revision: 1.4 $");
 script_name(english:"CentOS : RHSA-2006-0197");
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

if ( rpm_check(reference:"python-2.3.4-14.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- python-2.3.4-14.2\n';
if ( rpm_check(reference:"python-devel-2.3.4-14.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- python-devel-2.3.4-14.2\n';
if ( rpm_check(reference:"python-docs-2.3.4-14.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- python-docs-2.3.4-14.2\n';
if ( rpm_check(reference:"python-tools-2.3.4-14.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- python-tools-2.3.4-14.2\n';
if ( rpm_check(reference:"tkinter-2.3.4-14.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- tkinter-2.3.4-14.2\n';
if ( rpm_check(reference:"python-2.2.3-6.2", release:"CentOS-3", cpu:"ia64") )  faulty += '- python-2.2.3-6.2\n';
if ( rpm_check(reference:"python-devel-2.2.3-6.2", release:"CentOS-3", cpu:"ia64") )  faulty += '- python-devel-2.2.3-6.2\n';
if ( rpm_check(reference:"python-docs-2.2.3-6.2", release:"CentOS-3", cpu:"ia64") )  faulty += '- python-docs-2.2.3-6.2\n';
if ( rpm_check(reference:"python-tools-2.2.3-6.2", release:"CentOS-3", cpu:"ia64") )  faulty += '- python-tools-2.2.3-6.2\n';
if ( rpm_check(reference:"tkinter-2.2.3-6.2", release:"CentOS-3", cpu:"ia64") )  faulty += '- tkinter-2.2.3-6.2\n';
if ( rpm_check(reference:"python-1.5.2-43.72.1", release:"CentOS-3", cpu:"i386") )  faulty += '- python-1.5.2-43.72.1\n';
if ( rpm_check(reference:"python-devel-1.5.2-43.72.1", release:"CentOS-3", cpu:"i386") )  faulty += '- python-devel-1.5.2-43.72.1\n';
if ( rpm_check(reference:"python-docs-1.5.2-43.72.1", release:"CentOS-3", cpu:"i386") )  faulty += '- python-docs-1.5.2-43.72.1\n';
if ( rpm_check(reference:"python-tools-1.5.2-43.72.1", release:"CentOS-3", cpu:"i386") )  faulty += '- python-tools-1.5.2-43.72.1\n';
if ( rpm_check(reference:"tkinter-1.5.2-43.72.1", release:"CentOS-3", cpu:"i386") )  faulty += '- tkinter-1.5.2-43.72.1\n';
if ( rpm_check(reference:"python-2.2.3-6.2", release:"CentOS-3", cpu:"i386") )  faulty += '- python-2.2.3-6.2\n';
if ( rpm_check(reference:"python-devel-2.2.3-6.2", release:"CentOS-3", cpu:"i386") )  faulty += '- python-devel-2.2.3-6.2\n';
if ( rpm_check(reference:"python-tools-2.2.3-6.2", release:"CentOS-3", cpu:"i386") )  faulty += '- python-tools-2.2.3-6.2\n';
if ( rpm_check(reference:"tkinter-2.2.3-6.2", release:"CentOS-3", cpu:"i386") )  faulty += '- tkinter-2.2.3-6.2\n';
if ( rpm_check(reference:"python-docs-2.2.3-6.2", release:"CentOS-3", cpu:"i386") )  faulty += '- python-docs-2.2.3-6.2\n';
if ( rpm_check(reference:"python-2.2.3-6.2", release:"CentOS-3", cpu:"x86_64") )  faulty += '- python-2.2.3-6.2\n';
if ( rpm_check(reference:"python-devel-2.2.3-6.2", release:"CentOS-3", cpu:"x86_64") )  faulty += '- python-devel-2.2.3-6.2\n';
if ( rpm_check(reference:"python-tools-2.2.3-6.2", release:"CentOS-3", cpu:"x86_64") )  faulty += '- python-tools-2.2.3-6.2\n';
if ( rpm_check(reference:"tkinter-2.2.3-6.2", release:"CentOS-3", cpu:"x86_64") )  faulty += '- tkinter-2.2.3-6.2\n';
if ( rpm_check(reference:"python-docs-2.2.3-6.2", release:"CentOS-3", cpu:"x86_64") )  faulty += '- python-docs-2.2.3-6.2\n';
if ( rpm_check(reference:"python-2.3.4-14.2", release:"CentOS-4", cpu:"i386") )  faulty += '- python-2.3.4-14.2\n';
if ( rpm_check(reference:"python-devel-2.3.4-14.2", release:"CentOS-4", cpu:"i386") )  faulty += '- python-devel-2.3.4-14.2\n';
if ( rpm_check(reference:"python-docs-2.3.4-14.2", release:"CentOS-4", cpu:"i386") )  faulty += '- python-docs-2.3.4-14.2\n';
if ( rpm_check(reference:"python-tools-2.3.4-14.2", release:"CentOS-4", cpu:"i386") )  faulty += '- python-tools-2.3.4-14.2\n';
if ( rpm_check(reference:"tkinter-2.3.4-14.2", release:"CentOS-4", cpu:"i386") )  faulty += '- tkinter-2.3.4-14.2\n';
if ( rpm_check(reference:"python-2.3.4-14.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- python-2.3.4-14.2\n';
if ( rpm_check(reference:"python-devel-2.3.4-14.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- python-devel-2.3.4-14.2\n';
if ( rpm_check(reference:"python-docs-2.3.4-14.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- python-docs-2.3.4-14.2\n';
if ( rpm_check(reference:"python-tools-2.3.4-14.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- python-tools-2.3.4-14.2\n';
if ( rpm_check(reference:"tkinter-2.3.4-14.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- tkinter-2.3.4-14.2\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
