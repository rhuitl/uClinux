#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2005-384.

See also :

https://rhn.redhat.com/errata/RHSA-2005-384.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(21930);
 script_version("$Revision: 1.3 $");
 script_name(english:"CentOS : RHSA-2005-384");
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

if ( rpm_check(reference:"mozilla-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"x86_64") )  faulty += '- mozilla-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-chat-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"x86_64") )  faulty += '- mozilla-chat-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-devel-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"x86_64") )  faulty += '- mozilla-devel-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-dom-inspector-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"x86_64") )  faulty += '- mozilla-dom-inspector-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-js-debugger-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"x86_64") )  faulty += '- mozilla-js-debugger-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-mail-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"x86_64") )  faulty += '- mozilla-mail-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-nspr-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"x86_64") )  faulty += '- mozilla-nspr-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-nspr-devel-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"x86_64") )  faulty += '- mozilla-nspr-devel-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-nss-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"x86_64") )  faulty += '- mozilla-nss-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-nss-devel-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"x86_64") )  faulty += '- mozilla-nss-devel-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"ia64") )  faulty += '- mozilla-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-chat-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"ia64") )  faulty += '- mozilla-chat-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-devel-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"ia64") )  faulty += '- mozilla-devel-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-dom-inspector-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"ia64") )  faulty += '- mozilla-dom-inspector-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-js-debugger-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"ia64") )  faulty += '- mozilla-js-debugger-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-mail-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"ia64") )  faulty += '- mozilla-mail-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-nspr-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"ia64") )  faulty += '- mozilla-nspr-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-nspr-devel-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"ia64") )  faulty += '- mozilla-nspr-devel-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-nss-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"ia64") )  faulty += '- mozilla-nss-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-nss-devel-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"ia64") )  faulty += '- mozilla-nss-devel-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"i386") )  faulty += '- mozilla-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-chat-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"i386") )  faulty += '- mozilla-chat-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-devel-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"i386") )  faulty += '- mozilla-devel-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-dom-inspector-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"i386") )  faulty += '- mozilla-dom-inspector-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-js-debugger-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"i386") )  faulty += '- mozilla-js-debugger-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-mail-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"i386") )  faulty += '- mozilla-mail-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-nspr-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"i386") )  faulty += '- mozilla-nspr-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-nspr-devel-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"i386") )  faulty += '- mozilla-nspr-devel-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-nss-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"i386") )  faulty += '- mozilla-nss-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"mozilla-nss-devel-1.7.7-1.1.3.4.centos3", release:"CentOS-3", cpu:"i386") )  faulty += '- mozilla-nss-devel-1.7.7-1.1.3.4.centos3\n';
if ( rpm_check(reference:"glibc-2.2.4-32.20", release:"CentOS-3", cpu:"i386") )  faulty += '- glibc-2.2.4-32.20\n';
if ( rpm_check(reference:"glibc-common-2.2.4-32.20", release:"CentOS-3", cpu:"i386") )  faulty += '- glibc-common-2.2.4-32.20\n';
if ( rpm_check(reference:"glibc-devel-2.2.4-32.20", release:"CentOS-3", cpu:"i386") )  faulty += '- glibc-devel-2.2.4-32.20\n';
if ( rpm_check(reference:"glibc-profile-2.2.4-32.20", release:"CentOS-3", cpu:"i386") )  faulty += '- glibc-profile-2.2.4-32.20\n';
if ( rpm_check(reference:"nscd-2.2.4-32.20", release:"CentOS-3", cpu:"i386") )  faulty += '- nscd-2.2.4-32.20\n';
if ( rpm_check(reference:"glibc-2.2.4-32.20", release:"CentOS-3", cpu:"i686") )  faulty += '- glibc-2.2.4-32.20\n';
if ( rpm_check(reference:"kernel-BOOT-2.4.9-e.62", release:"CentOS-3", cpu:"i386") )  faulty += '- kernel-BOOT-2.4.9-e.62\n';
if ( rpm_check(reference:"kernel-doc-2.4.9-e.62", release:"CentOS-3", cpu:"i386") )  faulty += '- kernel-doc-2.4.9-e.62\n';
if ( rpm_check(reference:"kernel-headers-2.4.9-e.62", release:"CentOS-3", cpu:"i386") )  faulty += '- kernel-headers-2.4.9-e.62\n';
if ( rpm_check(reference:"kernel-source-2.4.9-e.62", release:"CentOS-3", cpu:"i386") )  faulty += '- kernel-source-2.4.9-e.62\n';
if ( rpm_check(reference:"kernel-2.4.9-e.62", release:"CentOS-3", cpu:"i686") )  faulty += '- kernel-2.4.9-e.62\n';
if ( rpm_check(reference:"kernel-debug-2.4.9-e.62", release:"CentOS-3", cpu:"i686") )  faulty += '- kernel-debug-2.4.9-e.62\n';
if ( rpm_check(reference:"kernel-enterprise-2.4.9-e.62", release:"CentOS-3", cpu:"i686") )  faulty += '- kernel-enterprise-2.4.9-e.62\n';
if ( rpm_check(reference:"kernel-smp-2.4.9-e.62", release:"CentOS-3", cpu:"i686") )  faulty += '- kernel-smp-2.4.9-e.62\n';
if ( rpm_check(reference:"kernel-summit-2.4.9-e.62", release:"CentOS-3", cpu:"i686") )  faulty += '- kernel-summit-2.4.9-e.62\n';
if ( rpm_check(reference:"kernel-2.4.9-e.62", release:"CentOS-3", cpu:"athlon") )  faulty += '- kernel-2.4.9-e.62\n';
if ( rpm_check(reference:"kernel-smp-2.4.9-e.62", release:"CentOS-3", cpu:"athlon") )  faulty += '- kernel-smp-2.4.9-e.62\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
