#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:006
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20879);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2006:006: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2006:006 (kernel).


The Linux kernel on SUSE Linux 10.0 has been updated to
fix following security problems:

- CVE-2006-0454: An extra dst release when ip_options_echo failed
was fixed.

This problem could be triggered by remote attackers and can
potentially crash the machine. This is possible even with
SuSEfirewall2 enabled.

This affects only SUSE Linux 10.0, all other SUSE distributions
are not affected.

- CVE-2005-3356: A double decrement in mq_open system call could lead
to local users crashing the machine.

- CVE-2005-3358: A 0 argument passed to the set_mempolicy() system
call could lead to a local user crashing the machine.

- CVE-2005-4605: Kernel memory could be leaked to user space through a
problem with seek() in /proc files .

- CVE-2005-3623: Remote users could set ACLs even on read-only
exported NFS Filesystems and so circumvent access control.

- CVE-2005-3808: A 32 bit integer overflow on 64bit mmap calls
could be used by local users to hang the machine.

- CVE-2005-4635: Add sanity checks for headers and payload of netlink
messages, which could be used by local attackers to crash the
machine.

Also various non-security bugs were fixed:
- Fix up patch for cpufreq drivers that do not initialize
current freq.
- Handle BIOS cpufreq changes gracefully.
- Updates to inotify handling.
- Various XEN Updates.
- Catches processor declarations with same ACPI id (P4HT)
- PowerPC: g5 thermal overtemp bug on fluid cooled systems.
- Fixed buffered ACPI events on a lot ASUS and some other machines.
- Fix fs/exec.c:788 (de_thread()) BUG_ON (OSDL 5170).


Solution : http://www.suse.de/security/advisories/2006_06_kernel.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kernel package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"Intel-536ep-4.69-14.3", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-2.6.13-15.8", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-nongpl-2.6.13-15.8", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.13-15.8", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-default-nongpl-2.6.13-15.8", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.13-15.8", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-nongpl-2.6.13-15.8", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.13-15.8", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.13-15.8", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-um-2.6.13-15.8", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-um-nongpl-2.6.13-15.8", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.13-15.8", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-nongpl-2.6.13-15.8", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"um-host-kernel-2.6.13-15.8", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xen-3.0_8259-0.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xen-devel-3.0_8259-0.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xen-doc-html-3.0_8259-0.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xen-doc-pdf-3.0_8259-0.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xen-doc-ps-3.0_8259-0.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xen-tools-3.0_8259-0.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xen-tools-ioemu-3.0_8259-0.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
