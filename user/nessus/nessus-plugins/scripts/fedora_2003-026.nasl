#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13665);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "Fedora Core 1 2003-026: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2003-026 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of your
Red Hat Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.


The kernel shipped with Fedora Core 1 was vulnerable to a bug in the
error return on a concurrent fork() with threaded exit() which could be
exploited by a user level program to crash the kernel.

In addition to this bug fix, the changelog below details various
other non security fixes that have been added.

* Mon Dec 01 2003 Dave Jones <davej@redhat.com>

- sys_tgkill wasn't enabled on IA32.

* Sun Nov 30 2003 Dave Jones <davej@redhat.com>

- Process scheduler fix.
 When doing sync wakeups we must not skip the notification of other cpus if
 the task is not on this runqueue.

* Wed Nov 26 2003 Justin M. Forbes <64bit_fedora@comcast.net>

- Merge required ia32 syscalls for AMD64
- [f]truncate64 for 32bit code fix

* Mon Nov 24 2003 Dave Jones <davej@redhat.com>

- Fix power-off on shutdown with ACPI.
- Add missing part of recent cmpci fix
- Drop CONFIG_NR_CPUS patch which was problematic.
- Fold futex-fix into main futex patch.
- Fix TG3 tqueue initialisation.
- Various NPTL fixes.

* Fri Nov 14 2003 Dave Jones <davej@redhat.com>

- Drop netfilter change which proved to be bad upstream.

* Thu Nov 13 2003 Justin M. Forbes <64bit_fedora@comcast.net>

- Fix NForce3 DMA and ATA133 on AMD64

* Wed Nov 12 2003 Dave Jones <davej@redhat.com>

- Fix syscall definitions on AMD64

* Tue Nov 11 2003 Dave Jones <davej@redhat.com>

- Fix Intel 440GX Interrupt routing.
- Fix waitqueue leak in cmpci driver.

* Mon Nov 10 2003 Dave Jones <davej@redhat.com>

- Kill noisy warnings in the DRM modules.
- Merge munged upstream x86-64.org patch for various AMD64 fixes.

* Mon Nov 03 2003 Dave Jones <davej@redhat.com>

- Further cleanups related to AMD64 build.

* Fri Oct 31 2003 Dave Jones <davej@redhat.com>

- Make AMD64 build.



Solution : http://www.fedoranews.org/updates/FEDORA-2003-026.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kernel package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kernel-2.4.22-1.2129.nptl", prefix:"kernel-", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
