#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2006-0526.

See also :

https://rhn.redhat.com/errata/RHSA-2006-0526.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(21905);
 script_version("$Revision: 1.4 $");
 script_name(english:"CentOS : RHSA-2006-0526");
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

if ( rpm_check(reference:"rh-postgresql-7.3.15-2", release:"CentOS-3", cpu:"i386") )  faulty += '- rh-postgresql-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-contrib-7.3.15-2", release:"CentOS-3", cpu:"i386") )  faulty += '- rh-postgresql-contrib-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-devel-7.3.15-2", release:"CentOS-3", cpu:"i386") )  faulty += '- rh-postgresql-devel-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-docs-7.3.15-2", release:"CentOS-3", cpu:"i386") )  faulty += '- rh-postgresql-docs-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-jdbc-7.3.15-2", release:"CentOS-3", cpu:"i386") )  faulty += '- rh-postgresql-jdbc-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-libs-7.3.15-2", release:"CentOS-3", cpu:"i386") )  faulty += '- rh-postgresql-libs-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-pl-7.3.15-2", release:"CentOS-3", cpu:"i386") )  faulty += '- rh-postgresql-pl-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-python-7.3.15-2", release:"CentOS-3", cpu:"i386") )  faulty += '- rh-postgresql-python-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-server-7.3.15-2", release:"CentOS-3", cpu:"i386") )  faulty += '- rh-postgresql-server-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-tcl-7.3.15-2", release:"CentOS-3", cpu:"i386") )  faulty += '- rh-postgresql-tcl-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-test-7.3.15-2", release:"CentOS-3", cpu:"i386") )  faulty += '- rh-postgresql-test-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-7.3.15-2", release:"CentOS-3", cpu:"x86_64") )  faulty += '- rh-postgresql-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-contrib-7.3.15-2", release:"CentOS-3", cpu:"x86_64") )  faulty += '- rh-postgresql-contrib-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-devel-7.3.15-2", release:"CentOS-3", cpu:"x86_64") )  faulty += '- rh-postgresql-devel-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-docs-7.3.15-2", release:"CentOS-3", cpu:"x86_64") )  faulty += '- rh-postgresql-docs-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-jdbc-7.3.15-2", release:"CentOS-3", cpu:"x86_64") )  faulty += '- rh-postgresql-jdbc-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-libs-7.3.15-2", release:"CentOS-3", cpu:"x86_64") )  faulty += '- rh-postgresql-libs-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-pl-7.3.15-2", release:"CentOS-3", cpu:"x86_64") )  faulty += '- rh-postgresql-pl-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-python-7.3.15-2", release:"CentOS-3", cpu:"x86_64") )  faulty += '- rh-postgresql-python-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-server-7.3.15-2", release:"CentOS-3", cpu:"x86_64") )  faulty += '- rh-postgresql-server-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-tcl-7.3.15-2", release:"CentOS-3", cpu:"x86_64") )  faulty += '- rh-postgresql-tcl-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-test-7.3.15-2", release:"CentOS-3", cpu:"x86_64") )  faulty += '- rh-postgresql-test-7.3.15-2\n';
if ( rpm_check(reference:"postgresql-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"ia64") )  faulty += '- postgresql-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-contrib-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"ia64") )  faulty += '- postgresql-contrib-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-devel-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"ia64") )  faulty += '- postgresql-devel-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-docs-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"ia64") )  faulty += '- postgresql-docs-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-jdbc-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"ia64") )  faulty += '- postgresql-jdbc-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-libs-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"ia64") )  faulty += '- postgresql-libs-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-pl-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"ia64") )  faulty += '- postgresql-pl-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-python-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"ia64") )  faulty += '- postgresql-python-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-server-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"ia64") )  faulty += '- postgresql-server-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-tcl-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"ia64") )  faulty += '- postgresql-tcl-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-test-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"ia64") )  faulty += '- postgresql-test-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"rh-postgresql-7.3.15-2", release:"CentOS-3", cpu:"ia64") )  faulty += '- rh-postgresql-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-contrib-7.3.15-2", release:"CentOS-3", cpu:"ia64") )  faulty += '- rh-postgresql-contrib-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-devel-7.3.15-2", release:"CentOS-3", cpu:"ia64") )  faulty += '- rh-postgresql-devel-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-docs-7.3.15-2", release:"CentOS-3", cpu:"ia64") )  faulty += '- rh-postgresql-docs-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-jdbc-7.3.15-2", release:"CentOS-3", cpu:"ia64") )  faulty += '- rh-postgresql-jdbc-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-libs-7.3.15-2", release:"CentOS-3", cpu:"ia64") )  faulty += '- rh-postgresql-libs-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-pl-7.3.15-2", release:"CentOS-3", cpu:"ia64") )  faulty += '- rh-postgresql-pl-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-python-7.3.15-2", release:"CentOS-3", cpu:"ia64") )  faulty += '- rh-postgresql-python-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-server-7.3.15-2", release:"CentOS-3", cpu:"ia64") )  faulty += '- rh-postgresql-server-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-tcl-7.3.15-2", release:"CentOS-3", cpu:"ia64") )  faulty += '- rh-postgresql-tcl-7.3.15-2\n';
if ( rpm_check(reference:"rh-postgresql-test-7.3.15-2", release:"CentOS-3", cpu:"ia64") )  faulty += '- rh-postgresql-test-7.3.15-2\n';
if ( rpm_check(reference:"postgresql-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"x86_64") )  faulty += '- postgresql-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-contrib-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"x86_64") )  faulty += '- postgresql-contrib-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-devel-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"x86_64") )  faulty += '- postgresql-devel-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-docs-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"x86_64") )  faulty += '- postgresql-docs-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-jdbc-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"x86_64") )  faulty += '- postgresql-jdbc-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-libs-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"i386") )  faulty += '- postgresql-libs-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-libs-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"x86_64") )  faulty += '- postgresql-libs-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-pl-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"x86_64") )  faulty += '- postgresql-pl-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-python-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"x86_64") )  faulty += '- postgresql-python-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-server-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"x86_64") )  faulty += '- postgresql-server-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-tcl-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"x86_64") )  faulty += '- postgresql-tcl-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-test-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"x86_64") )  faulty += '- postgresql-test-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"i386") )  faulty += '- postgresql-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-contrib-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"i386") )  faulty += '- postgresql-contrib-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-devel-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"i386") )  faulty += '- postgresql-devel-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-docs-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"i386") )  faulty += '- postgresql-docs-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-jdbc-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"i386") )  faulty += '- postgresql-jdbc-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-pl-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"i386") )  faulty += '- postgresql-pl-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-python-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"i386") )  faulty += '- postgresql-python-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-server-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"i386") )  faulty += '- postgresql-server-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-tcl-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"i386") )  faulty += '- postgresql-tcl-7.4.13-2.RHEL4.1\n';
if ( rpm_check(reference:"postgresql-test-7.4.13-2.RHEL4.1", release:"CentOS-4", cpu:"i386") )  faulty += '- postgresql-test-7.4.13-2.RHEL4.1\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
