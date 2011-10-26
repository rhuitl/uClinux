#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2006-0667.

See also :

https://rhn.redhat.com/errata/RHSA-2006-0667.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(22422);
 script_version("$Revision: 1.1 $");
 script_name(english:"CentOS : RHSA-2006-0667");
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

if ( rpm_check(reference:"seamonkey-1.0.5-0.0.1.el2.c2.1", release:"CentOS-3", cpu:"i386") )  faulty += '- seamonkey-1.0.5-0.0.1.el2.c2.1\n';
if ( rpm_check(reference:"seamonkey-chat-1.0.5-0.0.1.el2.c2.1", release:"CentOS-3", cpu:"i386") )  faulty += '- seamonkey-chat-1.0.5-0.0.1.el2.c2.1\n';
if ( rpm_check(reference:"seamonkey-devel-1.0.5-0.0.1.el2.c2.1", release:"CentOS-3", cpu:"i386") )  faulty += '- seamonkey-devel-1.0.5-0.0.1.el2.c2.1\n';
if ( rpm_check(reference:"seamonkey-dom-inspector-1.0.5-0.0.1.el2.c2.1", release:"CentOS-3", cpu:"i386") )  faulty += '- seamonkey-dom-inspector-1.0.5-0.0.1.el2.c2.1\n';
if ( rpm_check(reference:"seamonkey-js-debugger-1.0.5-0.0.1.el2.c2.1", release:"CentOS-3", cpu:"i386") )  faulty += '- seamonkey-js-debugger-1.0.5-0.0.1.el2.c2.1\n';
if ( rpm_check(reference:"seamonkey-mail-1.0.5-0.0.1.el2.c2.1", release:"CentOS-3", cpu:"i386") )  faulty += '- seamonkey-mail-1.0.5-0.0.1.el2.c2.1\n';
if ( rpm_check(reference:"seamonkey-nspr-1.0.5-0.0.1.el2.c2.1", release:"CentOS-3", cpu:"i386") )  faulty += '- seamonkey-nspr-1.0.5-0.0.1.el2.c2.1\n';
if ( rpm_check(reference:"seamonkey-nspr-devel-1.0.5-0.0.1.el2.c2.1", release:"CentOS-3", cpu:"i386") )  faulty += '- seamonkey-nspr-devel-1.0.5-0.0.1.el2.c2.1\n';
if ( rpm_check(reference:"seamonkey-nss-1.0.5-0.0.1.el2.c2.1", release:"CentOS-3", cpu:"i386") )  faulty += '- seamonkey-nss-1.0.5-0.0.1.el2.c2.1\n';
if ( rpm_check(reference:"seamonkey-nss-devel-1.0.5-0.0.1.el2.c2.1", release:"CentOS-3", cpu:"i386") )  faulty += '- seamonkey-nss-devel-1.0.5-0.0.1.el2.c2.1\n';
if ( rpm_check(reference:"gzip-1.3.3-13.rhel3", release:"CentOS-3", cpu:"ia64") )  faulty += '- gzip-1.3.3-13.rhel3\n';
if ( rpm_check(reference:"gzip-1.3.3-16.rhel4", release:"CentOS-4", cpu:"ia64") )  faulty += '- gzip-1.3.3-16.rhel4\n';
if ( rpm_check(reference:"gzip-1.3.3-13.rhel3", release:"CentOS-3", cpu:"i386") )  faulty += '- gzip-1.3.3-13.rhel3\n';
if ( rpm_check(reference:"gzip-1.3.3-13.rhel3", release:"CentOS-3", cpu:"x86_64") )  faulty += '- gzip-1.3.3-13.rhel3\n';
if ( rpm_check(reference:"gzip-1.3-19.rhel2", release:"CentOS-4", cpu:"i386") )  faulty += '- gzip-1.3-19.rhel2\n';
if ( rpm_check(reference:"gzip-1.3.3-16.rhel4", release:"CentOS-4", cpu:"x86_64") )  faulty += '- gzip-1.3.3-16.rhel4\n';
if ( rpm_check(reference:"gzip-1.3.3-16.rhel4", release:"CentOS-4", cpu:"i386") )  faulty += '- gzip-1.3.3-16.rhel4\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
