#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15790);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "Fedora Core 2 2004-450: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-450 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of
any
Linux operating system. The kernel handles the basic functions
of the operating system: memory allocation, process allocation, device
input and output, etc.

This update brings a rebase to 2.6.9, including various security
fixes incorporated into the upstream kernel, and also includes
Alan Cox's -ac patchset, which adds additional security fixes.


* Thu Nov 18 2004 Dave Jones
- Drop 2.6.9 changes that broke megaraid. (#139723)
- Update to 2.6.9-ac10, fixing the SATA problems (#139674)
- Update the OOM-killer tamer to upstream.
- Implement an RCU scheme for the SELinux AVC
- Improve on the OOM-killer taming patch.
- device-mapper: Remove duplicate kfree in dm_register_target error
path.
- Make SHA1 guard against misaligned accesses
- ASPM workaround for PCIe. (#123360)
- Hot-plug driver updates due to MSI change (#134290)
- Workaround for 80332 IOP hot-plug problem (#139041)
- ExpressCard hot-plug support for ICH6M (#131800)
- Fix boot crash on VIA systems (noted on x86-64)
- PPC64: Store correct backtracking info in ppc64 signal frames
- PPC64: Prevent HVSI from oopsing on hangup (#137912)
- Fix poor performance b/c of noncacheable mapping in 4g/4g (#130842)
- Fix PCI-X hotplug issues (#132852, #134290)
- Re-export force_sig() (#139503)
- Various fixes for more security issues from latest -ac patch.
- Fix d_find_alias brokenness (#137791)
- tg3: Fix fiber hw autoneg bounces (#138738)
- diskdump: Fix issue with NMI watchdog. (#138041)
- diskdump: Export disk_dump_state. (#138132)
- diskdump: Tickle NMI watchdog in diskdump_mdelay() (#138036)
- diskdump: Fix mem= for x86-64 (#138139)
- diskdump: Fix missing system_state setting. (#138130)
- diskdump: Fix diskdump completion message (#138028)
- Re-add aic host raid support.
- Take a few more export removal patches from 2.6.10rc
- SATA: Make AHCI work
- SATA: Core updates.
- S390: Fix Incorrect registers in core dumps. (#138206)
- S390: Fix up lcs device state. (#131167)
- S390: Fix possible qeth IP registration failure.
- S390: Support broadcast on z800/z900 HiperSockets
- S390: Allow FCP port to recover after aborted nameserver request.
- Flush error in pci_mmcfg_write (#129338)
- hugetlb_get_unmapped_area fix (#135364, #129525)
- Fix ia64 cyclone timer on ia64 (#137842, #136684)
- Fix ipv6 MTU calculation. (#130397)
- ACPI: Don't display messages about ACPI breakpoints. (#135856)
- Fix x86_64 copy_user_generic (#135655)
- lockd: remove hardcoded maximum NLM cookie length
- Fix SCSI bounce limit
- Disable polling mode on hotplug controllers in favour of interrupt
driven. (#138737)



Solution : http://www.fedoranews.org/blog/index.php?p=104
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
if ( rpm_check( reference:"kernel-2.6.9-   Release : 1.6_FC2", prefix:"kernel-", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
