#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2005-434.

See also :

https://rhn.redhat.com/errata/RHSA-2005-434.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(21939);
 script_version("$Revision: 1.3 $");
 script_name(english:"CentOS : RHSA-2005-434");
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

if ( rpm_check(reference:"firefox-1.0.4-1.4.1.centos4", release:"CentOS-4", cpu:"ia64") )  faulty += '- firefox-1.0.4-1.4.1.centos4\n';
if ( rpm_check(reference:"firefox-1.0.4-1.4.1.centos4", release:"CentOS-4", cpu:"i386") )  faulty += '- firefox-1.0.4-1.4.1.centos4\n';
if ( rpm_check(reference:"firefox-1.0.4-1.4.1.centos4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- firefox-1.0.4-1.4.1.centos4\n';
if ( rpm_check(reference:"galeon-1.2.14-1.2.5", release:"CentOS-2", cpu:"i386") )  faulty += '- galeon-1.2.14-1.2.5\n';
if ( rpm_check(reference:"mozilla-1.7.8-1.1.2.1.c2.1", release:"CentOS-2", cpu:"i386") )  faulty += '- mozilla-1.7.8-1.1.2.1.c2.1\n';
if ( rpm_check(reference:"mozilla-chat-1.7.8-1.1.2.1.c2.1", release:"CentOS-2", cpu:"i386") )  faulty += '- mozilla-chat-1.7.8-1.1.2.1.c2.1\n';
if ( rpm_check(reference:"mozilla-devel-1.7.8-1.1.2.1.c2.1", release:"CentOS-2", cpu:"i386") )  faulty += '- mozilla-devel-1.7.8-1.1.2.1.c2.1\n';
if ( rpm_check(reference:"mozilla-dom-inspector-1.7.8-1.1.2.1.c2.1", release:"CentOS-2", cpu:"i386") )  faulty += '- mozilla-dom-inspector-1.7.8-1.1.2.1.c2.1\n';
if ( rpm_check(reference:"mozilla-js-debugger-1.7.8-1.1.2.1.c2.1", release:"CentOS-2", cpu:"i386") )  faulty += '- mozilla-js-debugger-1.7.8-1.1.2.1.c2.1\n';
if ( rpm_check(reference:"mozilla-mail-1.7.8-1.1.2.1.c2.1", release:"CentOS-2", cpu:"i386") )  faulty += '- mozilla-mail-1.7.8-1.1.2.1.c2.1\n';
if ( rpm_check(reference:"mozilla-nspr-1.7.8-1.1.2.1.c2.1", release:"CentOS-2", cpu:"i386") )  faulty += '- mozilla-nspr-1.7.8-1.1.2.1.c2.1\n';
if ( rpm_check(reference:"mozilla-nspr-devel-1.7.8-1.1.2.1.c2.1", release:"CentOS-2", cpu:"i386") )  faulty += '- mozilla-nspr-devel-1.7.8-1.1.2.1.c2.1\n';
if ( rpm_check(reference:"mozilla-nss-1.7.8-1.1.2.1.c2.1", release:"CentOS-2", cpu:"i386") )  faulty += '- mozilla-nss-1.7.8-1.1.2.1.c2.1\n';
if ( rpm_check(reference:"mozilla-nss-devel-1.7.8-1.1.2.1.c2.1", release:"CentOS-2", cpu:"i386") )  faulty += '- mozilla-nss-devel-1.7.8-1.1.2.1.c2.1\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
