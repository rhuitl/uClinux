#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2005-793.

See also :

https://rhn.redhat.com/errata/RHSA-2005-793.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(21965);
 script_version("$Revision: 1.3 $");
 script_name(english:"CentOS : RHSA-2005-793");
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

if ( rpm_check(reference:"netpbm-10.25-2.EL4.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- netpbm-10.25-2.EL4.2\n';
if ( rpm_check(reference:"netpbm-devel-10.25-2.EL4.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- netpbm-devel-10.25-2.EL4.2\n';
if ( rpm_check(reference:"netpbm-progs-10.25-2.EL4.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- netpbm-progs-10.25-2.EL4.2\n';
if ( rpm_check(reference:"netpbm-10.25-2.EL4.2", release:"CentOS-4", cpu:"i386") )  faulty += '- netpbm-10.25-2.EL4.2\n';
if ( rpm_check(reference:"netpbm-devel-10.25-2.EL4.2", release:"CentOS-4", cpu:"i386") )  faulty += '- netpbm-devel-10.25-2.EL4.2\n';
if ( rpm_check(reference:"netpbm-progs-10.25-2.EL4.2", release:"CentOS-4", cpu:"i386") )  faulty += '- netpbm-progs-10.25-2.EL4.2\n';
if ( rpm_check(reference:"netpbm-10.25-2.EL4.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- netpbm-10.25-2.EL4.2\n';
if ( rpm_check(reference:"netpbm-devel-10.25-2.EL4.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- netpbm-devel-10.25-2.EL4.2\n';
if ( rpm_check(reference:"netpbm-progs-10.25-2.EL4.2", release:"CentOS-4", cpu:"x86_64") )  faulty += '- netpbm-progs-10.25-2.EL4.2\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
