#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2005-518.

See also :

https://rhn.redhat.com/errata/RHSA-2005-518.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(21836);
 script_version("$Revision: 1.4 $");
 script_name(english:"CentOS : RHSA-2005-518");
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

if ( rpm_check(reference:"telnet-0.17-20.EL2.4", release:"CentOS-4", cpu:"i386") )  faulty += '- telnet-0.17-20.EL2.4\n';
if ( rpm_check(reference:"telnet-server-0.17-20.EL2.4", release:"CentOS-4", cpu:"i386") )  faulty += '- telnet-server-0.17-20.EL2.4\n';
if ( rpm_check(reference:"gaim-1.3.1-0.el3", release:"CentOS-4", cpu:"i386") )  faulty += '- gaim-1.3.1-0.el3\n';
if ( rpm_check(reference:"gaim-1.3.1-0.el3", release:"CentOS-4", cpu:"x86_64") )  faulty += '- gaim-1.3.1-0.el3\n';
if ( rpm_check(reference:"gaim-1.3.1-0.el3", release:"CentOS-3", cpu:"ia64") )  faulty += '- gaim-1.3.1-0.el3\n';
if ( rpm_check(reference:"gaim-1.3.1-0.el4", release:"CentOS-4", cpu:"ia64") )  faulty += '- gaim-1.3.1-0.el4\n';
if ( rpm_check(reference:"gaim-1.3.1-0.el3", release:"CentOS-3", cpu:"i386") )  faulty += '- gaim-1.3.1-0.el3\n';
if ( rpm_check(reference:"gaim-1.3.1-0.el3", release:"CentOS-3", cpu:"x86_64") )  faulty += '- gaim-1.3.1-0.el3\n';
if ( rpm_check(reference:"bzip2-1.0.1-4.EL2.1", release:"CentOS-3", cpu:"i386") )  faulty += '- bzip2-1.0.1-4.EL2.1\n';
if ( rpm_check(reference:"bzip2-devel-1.0.1-4.EL2.1", release:"CentOS-3", cpu:"i386") )  faulty += '- bzip2-devel-1.0.1-4.EL2.1\n';
if ( rpm_check(reference:"bzip2-libs-1.0.1-4.EL2.1", release:"CentOS-3", cpu:"i386") )  faulty += '- bzip2-libs-1.0.1-4.EL2.1\n';
if ( rpm_check(reference:"gmc-4.5.51-36.8", release:"CentOS-3", cpu:"i386") )  faulty += '- gmc-4.5.51-36.8\n';
if ( rpm_check(reference:"mc-4.5.51-36.8", release:"CentOS-3", cpu:"i386") )  faulty += '- mc-4.5.51-36.8\n';
if ( rpm_check(reference:"mcserv-4.5.51-36.8", release:"CentOS-3", cpu:"i386") )  faulty += '- mcserv-4.5.51-36.8\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
