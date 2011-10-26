#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
desc = "
Synopsis :

The remote host is missing a security update.

Description :

The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2005-799.

See also :

https://rhn.redhat.com/errata/RHSA-2005-799.html

Solution :

Upgrade to the newest packages by doing :

  yum update

Risk factor :

High";

if ( description )
{
 script_id(21860);
 script_version("$Revision: 1.4 $");
 script_name(english:"CentOS : RHSA-2005-799");
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

if ( rpm_check(reference:"ruby-1.6.8-9.EL3.4", release:"CentOS-3", cpu:"ia64") )  faulty += '- ruby-1.6.8-9.EL3.4\n';
if ( rpm_check(reference:"ruby-devel-1.6.8-9.EL3.4", release:"CentOS-3", cpu:"ia64") )  faulty += '- ruby-devel-1.6.8-9.EL3.4\n';
if ( rpm_check(reference:"ruby-docs-1.6.8-9.EL3.4", release:"CentOS-3", cpu:"ia64") )  faulty += '- ruby-docs-1.6.8-9.EL3.4\n';
if ( rpm_check(reference:"ruby-libs-1.6.8-9.EL3.4", release:"CentOS-3", cpu:"ia64") )  faulty += '- ruby-libs-1.6.8-9.EL3.4\n';
if ( rpm_check(reference:"ruby-mode-1.6.8-9.EL3.4", release:"CentOS-3", cpu:"ia64") )  faulty += '- ruby-mode-1.6.8-9.EL3.4\n';
if ( rpm_check(reference:"ruby-tcltk-1.6.8-9.EL3.4", release:"CentOS-3", cpu:"ia64") )  faulty += '- ruby-tcltk-1.6.8-9.EL3.4\n';
if ( rpm_check(reference:"ruby-1.8.1-7.EL4.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- ruby-1.8.1-7.EL4.2\n';
if ( rpm_check(reference:"ruby-devel-1.8.1-7.EL4.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- ruby-devel-1.8.1-7.EL4.2\n';
if ( rpm_check(reference:"ruby-docs-1.8.1-7.EL4.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- ruby-docs-1.8.1-7.EL4.2\n';
if ( rpm_check(reference:"ruby-libs-1.8.1-7.EL4.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- ruby-libs-1.8.1-7.EL4.2\n';
if ( rpm_check(reference:"ruby-mode-1.8.1-7.EL4.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- ruby-mode-1.8.1-7.EL4.2\n';
if ( rpm_check(reference:"ruby-tcltk-1.8.1-7.EL4.2", release:"CentOS-4", cpu:"ia64") )  faulty += '- ruby-tcltk-1.8.1-7.EL4.2\n';
if ( rpm_check(reference:"irb-1.6.8-9.EL3.4", release:"CentOS-3", cpu:"i386") )  faulty += '- irb-1.6.8-9.EL3.4\n';
if ( rpm_check(reference:"ruby-docs-1.6.8-9.EL3.4", release:"CentOS-3", cpu:"i386") )  faulty += '- ruby-docs-1.6.8-9.EL3.4\n';
if ( rpm_check(reference:"ruby-tcltk-1.6.8-9.EL3.4", release:"CentOS-3", cpu:"i386") )  faulty += '- ruby-tcltk-1.6.8-9.EL3.4\n';
if ( rpm_check(reference:"ruby-1.6.8-9.EL3.4", release:"CentOS-3", cpu:"i386") )  faulty += '- ruby-1.6.8-9.EL3.4\n';
if ( rpm_check(reference:"ruby-devel-1.6.8-9.EL3.4", release:"CentOS-3", cpu:"i386") )  faulty += '- ruby-devel-1.6.8-9.EL3.4\n';
if ( rpm_check(reference:"ruby-libs-1.6.8-9.EL3.4", release:"CentOS-3", cpu:"i386") )  faulty += '- ruby-libs-1.6.8-9.EL3.4\n';
if ( rpm_check(reference:"ruby-mode-1.6.8-9.EL3.4", release:"CentOS-3", cpu:"i386") )  faulty += '- ruby-mode-1.6.8-9.EL3.4\n';
if ( rpm_check(reference:"irb-1.6.8-9.EL3.4", release:"CentOS-3", cpu:"x86_64") )  faulty += '- irb-1.6.8-9.EL3.4\n';
if ( rpm_check(reference:"ruby-tcltk-1.6.8-9.EL3.4", release:"CentOS-3", cpu:"x86_64") )  faulty += '- ruby-tcltk-1.6.8-9.EL3.4\n';
if ( rpm_check(reference:"ruby-docs-1.6.8-9.EL3.4", release:"CentOS-3", cpu:"x86_64") )  faulty += '- ruby-docs-1.6.8-9.EL3.4\n';
if ( rpm_check(reference:"ruby-1.6.8-9.EL3.4", release:"CentOS-3", cpu:"x86_64") )  faulty += '- ruby-1.6.8-9.EL3.4\n';
if ( rpm_check(reference:"ruby-devel-1.6.8-9.EL3.4", release:"CentOS-3", cpu:"x86_64") )  faulty += '- ruby-devel-1.6.8-9.EL3.4\n';
if ( rpm_check(reference:"ruby-libs-1.6.8-9.EL3.4", release:"CentOS-3", cpu:"x86_64") )  faulty += '- ruby-libs-1.6.8-9.EL3.4\n';
if ( rpm_check(reference:"ruby-mode-1.6.8-9.EL3.4", release:"CentOS-3", cpu:"x86_64") )  faulty += '- ruby-mode-1.6.8-9.EL3.4\n';
if ( rpm_check(reference:"binutils-2.11.90.0.8-12.5", release:"CentOS-3", cpu:"i386") )  faulty += '- binutils-2.11.90.0.8-12.5\n';
if ( rpm_check(reference:"libuser-0.32-1.el2.1", release:"CentOS-3", cpu:"i386") )  faulty += '- libuser-0.32-1.el2.1\n';
if ( rpm_check(reference:"libuser-devel-0.32-1.el2.1", release:"CentOS-3", cpu:"i386") )  faulty += '- libuser-devel-0.32-1.el2.1\n';
if ( rpm_check(reference:"losetup-2.11g-9", release:"CentOS-3", cpu:"i386") )  faulty += '- losetup-2.11g-9\n';
if ( rpm_check(reference:"mount-2.11g-9", release:"CentOS-3", cpu:"i386") )  faulty += '- mount-2.11g-9\n';
if ( rpm_check(reference:"util-linux-2.11f-20.8", release:"CentOS-3", cpu:"i386") )  faulty += '- util-linux-2.11f-20.8\n';
if ( rpm_check(reference:"irb-1.6.4-2.AS21.2", release:"CentOS-3", cpu:"i386") )  faulty += '- irb-1.6.4-2.AS21.2\n';
if ( rpm_check(reference:"ruby-1.6.4-2.AS21.2", release:"CentOS-3", cpu:"i386") )  faulty += '- ruby-1.6.4-2.AS21.2\n';
if ( rpm_check(reference:"ruby-devel-1.6.4-2.AS21.2", release:"CentOS-3", cpu:"i386") )  faulty += '- ruby-devel-1.6.4-2.AS21.2\n';
if ( rpm_check(reference:"ruby-docs-1.6.4-2.AS21.2", release:"CentOS-3", cpu:"i386") )  faulty += '- ruby-docs-1.6.4-2.AS21.2\n';
if ( rpm_check(reference:"ruby-libs-1.6.4-2.AS21.2", release:"CentOS-3", cpu:"i386") )  faulty += '- ruby-libs-1.6.4-2.AS21.2\n';
if ( rpm_check(reference:"ruby-tcltk-1.6.4-2.AS21.2", release:"CentOS-3", cpu:"i386") )  faulty += '- ruby-tcltk-1.6.4-2.AS21.2\n';
if ( rpm_check(reference:"openssl-0.9.6b-40", release:"CentOS-3", cpu:"i386") )  faulty += '- openssl-0.9.6b-40\n';
if ( rpm_check(reference:"openssl-0.9.6b-40", release:"CentOS-3", cpu:"i686") )  faulty += '- openssl-0.9.6b-40\n';
if ( rpm_check(reference:"openssl-devel-0.9.6b-40", release:"CentOS-3", cpu:"i386") )  faulty += '- openssl-devel-0.9.6b-40\n';
if ( rpm_check(reference:"openssl-perl-0.9.6b-40", release:"CentOS-3", cpu:"i386") )  faulty += '- openssl-perl-0.9.6b-40\n';
if ( rpm_check(reference:"openssl095a-0.9.5a-26", release:"CentOS-3", cpu:"i386") )  faulty += '- openssl095a-0.9.5a-26\n';
if ( rpm_check(reference:"openssl096-0.9.6-27", release:"CentOS-3", cpu:"i386") )  faulty += '- openssl096-0.9.6-27\n';
if ( faulty ) security_hole(port:0, data:desc + '\n\nPlugin output:\n\nThe following RPMs need to be updated :\n' + faulty);
