#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:067
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20282);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2005:067: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:067 (kernel).


This kernel update for SUSE Linux 10.0 contains fixes for XEN, various
security fixes and bug fixes.

This update includes a more recent snapshot of the upcoming XEN 3.0.
Many bugs have been fixed. Stability for x86_64 has been improved.
Stability has been improved for SMP, and now both i586 and x86_64
kernels are built with SMP support.

It also contains several security fixes :

- CVE-2005-3783: A check in ptrace(2) handling that finds out if
a process is attaching to itself was incorrect and could be used
by a local attacker to crash the machine.

- CVE-2005-3784: A check in reaping of terminating child processes did
not consider ptrace(2) attached processes and would leave a ptrace
reference dangling. This could lead to a local user being able to
crash the machine.

- CVE-2005-3271: A task leak problem when releasing POSIX timers was
fixed. This could lead to local users causing a local denial of
service by exhausting system memory.

- CVE-2005-3805: A locking problem in POSIX timer handling could
be used by a local attacker on a SMP system to deadlock the machine.

- CVE-2005-3181: A problem in the Linux auditing code could lead
to a memory leak which finally could exhaust system memory of
a machine.

- CVE-2005-2973: An infinite loop in the IPv6 UDP loopback handling
can be easily triggered by a local user and lead to a denial
of service.

- CVE-2005-3806: A bug in IPv6 flow label handling code could be used
by a local attacker to free non-allocated memory and in turn corrupt
kernel memory and likely crash the machine.

- CVE-2005-3807: A memory kernel leak in VFS lease handling can
exhaust the machine memory and so cause a local denial of
service. This is seen in regular Samba use and could also be
triggered by local attackers.

- CVE-2005-3055: Unplugging an user space controlled USB device with
an URB pending in user space could crash the kernel. This can be
easily triggered by local attacker.

- CVE-2005-3180: Fixed incorrect padding in Orinoco wireless driver,
which could expose kernel data to the air.

- CVE-2005-3044: Missing sockfd_put() calls in routing_ioctl() leaked
file handles which in turn could exhaust system memory.

- CVE-2005-3527: A race condition in do_coredump in signal.c allows
local users to cause a denial of service (machine hang) by triggering
a core dump in one thread while another thread has a pending SIGSTOP.



Solution : http://www.suse.de/security/advisories/2005_67_kernel.html
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
if ( rpm_check( reference:"Intel-536ep-4.69-14.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-2.6.13-15.7", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-nongpl-2.6.13-15.7", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.13-15.7", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-default-nongpl-2.6.13-15.7", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.13-15.7", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-nongpl-2.6.13-15.7", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.13-15.7", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.13-15.7", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-um-2.6.13-15.7", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-um-nongpl-2.6.13-15.7", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.13-15.7", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-nongpl-2.6.13-15.7", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"um-host-kernel-2.6.13-15.7", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xen-3.0_7608-2.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xen-devel-3.0_7608-2.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xen-doc-html-3.0_7608-2.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xen-doc-pdf-3.0_7608-2.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xen-doc-ps-3.0_7608-2.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xen-tools-3.0_7608-2.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xen-tools-ioemu-3.0_7608-2.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
