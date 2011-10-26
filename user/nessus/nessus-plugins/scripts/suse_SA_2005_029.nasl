#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:029
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18462);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "SUSE-SA:2005:029: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:029 (kernel).


The Linux kernel is the core component of the Linux system.

This update fixes various security as well as non-security problems
discovered since the last round of kernel updates.


The following security problems have been fixed:

- when creating directories on ext2 filesystems the kernel did not
zero initialize the memory allocated. Therefore potentially
sensitive information could be exposed to users (CVE-2005-0400).

All SUSE LINUX based products are affected.

- local users can crash the kernel via a crafted ELF library or
executable, which causes a free of an invalid pointer
(CVE-2005-0749).

All SUSE LINUX based products are affected.

- local users could gain root access via a bluetooth socket
(CVE-2005-0750).

The fix for this problem was missing in SUSE LINUX 9.3 only.

- local users could gain root access by causing a core dump of
specially crafted ELF executables (CVE-2005-1263).

The problem is believed to be not exploitable on any SUSE LINUX
based product. The patch is included nevertheless.

- on the x86-64 platform various bugs allowed local users to crash
the kernel or CPU (CVE-2005-0756, CVE-2005-1762, CVE-2005-1764,
CVE-2005-1765)

All SUSE LINUX based products on the x86-64 architecture are
affected.

- an overflow in the x86-64 ptrace code allowed local users to
write a few bytes into kernel memory pages they normally
shouldn't have access to (CVE-2005-1763).

SLES 9 and SUSE LINUX 9.1-9.3 on the x86-64 architecture are
affected.

- insufficient checks in the 32bit DRM ioctl functions could allow
unprivileged local users to gain root access.

SLES 9 and SUSE LINUX 9.1-9.3 on the x86-64 architecture are
affected.



Solution : http://www.suse.de/security/advisories/2005_29_kernel.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kernel package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"k_athlon-2.4.20-136", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.20-136", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.20-136", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.20-136", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.20.SuSE-136", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"Intel-536ep-4.62-25", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"Intel-v92ham-4.53-25", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.21-291", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.21-291", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.21-291", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp4G-2.4.21-291", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_um-2.4.21-291", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-291", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ltmodem-8.26a-214", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-2.6.5-7.155.29", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.5-7.155.29", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.5-7.155.29", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.5-7.155.29", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.5-7.155.29", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ltmodem-2.6.2-38.15", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-docs-2.6.5-7.155.29", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"Intel-536ep-4.69-5.9", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-2.6.8-24.16", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-nongpl-2.6.8-24.16", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.8-24.16", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-default-nongpl-2.6.8-24.16", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.8-24.16", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-nongpl-2.6.8-24.16", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.8-24.16", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.8-24.16", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-um-2.6.8-24.16", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-um-nongpl-2.6.8-24.16", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ltmodem-8.31a8-6.9", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"um-host-install-initrd-1.0-48.8", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"um-host-kernel-2.6.8-24.16", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-docs-2.6.8-24.16", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"Intel-536ep-4.69-10.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dprobes-3.6.5-8.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-2.6.11.4-21.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-nongpl-2.6.11.4-21.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.11.4-21.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-default-nongpl-2.6.11.4-21.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.11.4-21.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-nongpl-2.6.11.4-21.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.11.4-21.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.11.4-21.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-um-2.6.11.4-21.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-um-nongpl-2.6.11.4-21.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.11.4-21.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-nongpl-2.6.11.4-21.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ltmodem-8.31a10-7.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"um-host-install-initrd-1.0-50.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"um-host-kernel-2.6.11.4-21.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-docs-2.6.11.4-21.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
