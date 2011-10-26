#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19722);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2555");
 
 name["english"] = "Fedora Core 4 2005-820: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-820 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of
the Red Hat Linux operating system. The kernel handles the basic
functions of the operating system: memory allocation, process
allocation, device input and output, etc.


* Fri Aug 26 2005 Dave Jones <davej redhat com> [2.6.12-1.1447_FC4]
- Better identify local builds. (#159696)
- Fix disk/net dump & netconsole. (#152586)
- Fix up sleeping in invalid context in sym2 driver. (#164995)
- Fix 'semaphore is not ready' error in snd-intel8x0m.
- Restore hwclock functionality on some systems. (#144894)
- Merge patches proposed for 2.6.12.6
- Fix typo in ALPS driver.
- Fix 'No sense' error with Transcend USB key. (#162559)
- Fix up ide-scsi check for medium not present. (#160868)
- powernow-k8 driver update from 2.6.13rc7.

* Tue Aug 23 2005 Dave Jones <davej redhat com> [2.6.12-1.1435_FC4]
- Work around AMD x86-64 errata 122.

* Tue Aug 23 2005 Rik van Riel <riel redhat com>
- upgrade to today's Xen snapshot

* Mon Aug 22 2005 Rik van Riel <riel redhat com>
- make sure that the vsyscall-note is linked in so the right glibc is used

* Sun Aug 21 2005 Rik van Riel <riel redhat com>
- fix the Xen vsyscall problem

* Thu Aug 18 2005 David Woodhouse <dwmw2 redhat com>
- Don't probe 8250 ports on ppc32 unless they're in the device tree
- Enable ISDN, 8250 console, i8042 keyboard controller on ppc32
- Audit updates from git tree

* Wed Aug 17 2005 Rik van Riel <riel redhat com>
- temporarily disable the vsyscall page for Xen

* Tue Aug 16 2005 Dave Jones <davej redhat com>
- Restrict ipsec socket policy loading to CAP_NET_ADMIN. (CVE-2005-2555)

* Mon Aug 15 2005 Rik van Riel <riel redhat com>
- upgrade Xen to a newer version

* Mon Aug 15 2005 Dave Jones <davej redhat com>
- 2.6.11.5
- Fix module_verify_elf check that rejected valid .ko files. (#165528)

* Thu Aug 11 2005 Dave Jones <davej redhat com>
- Audit speedup in syscall path.
- Update to a newer ACPI drop.

* Fri Aug  5 2005 Dave Jones <davej redhat com> [2.6.12-1.1420_FC4]
- update to final 2.6.12.4 patchset.
- ACPI update to 20050729.
- Disable experimental ACPI HOTKEY driver. (#163355)

* Thu Aug  4 2005 Dave Jones <davej redhat com>
- Enable Amiga partition support. (#149802)

* Wed Aug  3 2005 Dave Jones <davej redhat com> [2.6.12-1.1411_FC4]
- Include pre-release 2.6.12.4 patchset
- Silence some messages from PowerMac thermal driver. (#158739)
- nfs server intermitently claimed ENOENT on existing files or directories. (#1
50759)
- Stop usbhid driver incorrectly claiming Wireless Security Lock as a mouse. (#
147479)
- Further NFSD fixing for non-standard ports.
- Fix up miscalculated i_nlink in /proc (#162418)
- Fix addrlen checks in selinux_socket_connect. (#164165)

* Thu Jul 28 2005 Dave Jones <davej redhat com>
- Fix compilation with older gcc. (#164041)




Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kernel package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kernel-2.6.12-1.1447_FC4", prefix:"kernel-", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kernel-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-2555", value:TRUE);
}
