#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18604);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1761", "CVE-2005-1913");
 
 name["english"] = "Fedora Core 4 2005-510: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-510 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.


* Wed Jun 29 2005 Dave Jones <davej@redhat.com>
- 2.6.12.2

* Mon Jun 27 2005 Dave Jones <davej@redhat.com>
- Disable multipath caches. (#161168)
- Reenable AMD756 I2C driver for x86-64. (#159609)
- Add more IBM r40e BIOS's to the C2/C3 blacklist.

* Thu Jun 23 2005 Dave Jones <davej@redhat.com>
- Make orinoco driver suck less.
(Scanning/roaming/ethtool support).
- Exec-shield randomisation fix.
- pwc driver warning fix.
- Prevent potential oops in tux with symlinks. (#160219)

* Wed Jun 22 2005 Dave Jones <davej@redhat.com>
- 2.6.12.1
- Clean up subthread exec (CVE-2005-1913)
- ia64 ptrace + sigrestore_context (CVE-2005-1761)

* Wed Jun 22 2005 David Woodhouse <dwmw2@redhat.com>
- Update audit support

* Mon Jun 20 2005 Dave Jones <davej@redhat.com>
- Rebase to 2.6.12
- Temporarily drop Alans IDE fixes whilst they get redone.
- Enable userspace queueing of ipv6 packets.

* Tue Jun  7 2005 Dave Jones <davej@redhat.com>
- Drop recent b44 changes which broke some setups.



Solution : http://fedoranews.org//mediawiki/index.php/Fedora_Core_4_Update:_kernel-2.6.12-1.1387_FC4
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
if ( rpm_check( reference:"kernel-2.6.12-1.1387_FC4", prefix:"kernel-", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kernel-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-1761", value:TRUE);
 set_kb_item(name:"CVE-2005-1913", value:TRUE);
}
