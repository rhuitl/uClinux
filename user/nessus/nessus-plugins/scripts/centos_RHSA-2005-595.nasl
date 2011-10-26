#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2005-595.

See also :

https://rhn.redhat.com/errata/RHSA-2005-595.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(21950);
 script_version("$Revision: 1.3 $");
 script_name(english:"CentOS : RHSA-2005-595");
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

if ( rpm_check(reference:"squirrelmail-1.4.3a-10.EL3.centos.1", release:"CentOS-3") )  faulty += '- squirrelmail-1.4.3a-10.EL3.centos.1\n';
if ( rpm_check(reference:"squirrelmail-1.4.3a-11.EL4", release:"CentOS-4") )  faulty += '- squirrelmail-1.4.3a-11.EL4\n';
if ( rpm_check(reference:"squirrelmail-1.4.3a-11.EL4.centos4", release:"CentOS-4") )  faulty += '- squirrelmail-1.4.3a-11.EL4.centos4\n';
if ( rpm_check(reference:"squirrelmail-1.4.3a-11.EL3.centos.1", release:"CentOS-3") )  faulty += '- squirrelmail-1.4.3a-11.EL3.centos.1\n';
if ( rpm_check(reference:"squirrelmail-1.4.3a-12.EL4.centos4", release:"CentOS-4") )  faulty += '- squirrelmail-1.4.3a-12.EL4.centos4\n';
if ( rpm_check(reference:"dump-0.4b25-1.72.2", release:"CentOS-3", cpu:"i386") )  faulty += '- dump-0.4b25-1.72.2\n';
if ( rpm_check(reference:"rmt-0.4b25-1.72.2", release:"CentOS-3", cpu:"i386") )  faulty += '- rmt-0.4b25-1.72.2\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
