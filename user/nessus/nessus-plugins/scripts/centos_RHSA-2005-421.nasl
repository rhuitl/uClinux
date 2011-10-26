#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2005-421.

See also :

https://rhn.redhat.com/errata/RHSA-2005-421.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(21823);
 script_version("$Revision: 1.4 $");
 script_name(english:"CentOS : RHSA-2005-421");
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

if ( rpm_check(reference:"arpwatch-2.1a13-9.RHEL4", release:"CentOS-3", cpu:"i386") )  faulty += '- arpwatch-2.1a13-9.RHEL4\n';
if ( rpm_check(reference:"libpcap-0.8.3-9.RHEL4", release:"CentOS-3", cpu:"i386") )  faulty += '- libpcap-0.8.3-9.RHEL4\n';
if ( rpm_check(reference:"tcpdump-3.8.2-9.RHEL4", release:"CentOS-3", cpu:"i386") )  faulty += '- tcpdump-3.8.2-9.RHEL4\n';
if ( rpm_check(reference:"libpcap-0.7.2-7.E3.5", release:"CentOS-3", cpu:"i386") )  faulty += '- libpcap-0.7.2-7.E3.5\n';
if ( rpm_check(reference:"libpcap-0.7.2-7.E3.5", release:"CentOS-3", cpu:"x86_64") )  faulty += '- libpcap-0.7.2-7.E3.5\n';
if ( rpm_check(reference:"tcpdump-3.7.2-7.E3.5", release:"CentOS-3", cpu:"x86_64") )  faulty += '- tcpdump-3.7.2-7.E3.5\n';
if ( rpm_check(reference:"arpwatch-2.1a11-7.E3.5", release:"CentOS-3", cpu:"x86_64") )  faulty += '- arpwatch-2.1a11-7.E3.5\n';
if ( rpm_check(reference:"tcpdump-3.7.2-7.E3.5", release:"CentOS-3", cpu:"i386") )  faulty += '- tcpdump-3.7.2-7.E3.5\n';
if ( rpm_check(reference:"arpwatch-2.1a11-7.E3.5", release:"CentOS-3", cpu:"i386") )  faulty += '- arpwatch-2.1a11-7.E3.5\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
