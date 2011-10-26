#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19648);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0210", "CVE-2005-0384", "CVE-2005-0400", "CVE-2005-0449", "CVE-2005-0531", "CVE-2005-0736", "CVE-2005-0749", "CVE-2005-0750", "CVE-2005-0767", "CVE-2005-0815");
 
 name["english"] = "Fedora Core 3 2005-313: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-313 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

This update rebases the kernel to the latest upstream stable release,
which fixes a number of security issues. Notably:
- CVE-2005-0210 : dst leak
- CVE-2005-0384 : ppp dos
- CVE-2005-0531 : Sign handling issues.
- CVE-2005-0400 : EXT2 information leak.
- CVE-2005-0449 : Remote oops.
- CVE-2005-0736 : Epoll overflow
- CVE-2005-0749 : ELF loader may kfree wrong memory.
- CVE-2005-0750 : Missing range checking in bluetooth
- CVE-2005-0767 : drm race in radeon
- CVE-2005-0815 : Corrupt isofs images could cause oops

Additionally, a large number of improvements have come from the
2.6.10 -> 2.6.11 transition.

This update requires you are running the latest udev package, and
also (if you are using SELinux) the latest selinux policy packages.


* Thu Apr  7 2005 Dave Jones <davej redhat com>
- Update to 2.6.11.7
- Set CFQ as default elevator again.

* Tue Apr  5 2005 Dave Jones <davej redhat com>
- Disable slab debug.
- Re-add the pwc driver. (#152593)

* Wed Mar 30 2005 Dave Jones <davej redhat com>
- x86_64: Only free PMDs and PUDs after other CPUs have been flushed

* Sat Mar 26 2005 Dave Jones <davej redhat com>
- Update to 2.6.11.6

* Tue Mar 22 2005 Dave Jones <davej redhat com>
- Fix up several calls to memset with swapped arguments.

* Sat Mar 19 2005 Dave Jones <davej redhat com>
- Update to 2.6.11.5

* Fri Mar 18 2005 Dave Jones <davej redhat com>
- Kjournald oops race. (#146344)

* Tue Mar 15 2005 Dave Jones <davej redhat com>
- Update to 2.6.11.4

* Thu Mar 10 2005 Dave Jones <davej redhat com>
- Update to 2.6.11.2
- Reenable advansys driver for x86

* Fri Mar  4 2005 Dave Jones <davej redhat com>
- Fix up ACPI vs keyboard controller problem.
- Fix up Altivec usage on PPC/PPC64.

* Fri Mar  4 2005 Dave Jones <davej redhat com>
- Finger the programs that try to read from /dev/mem.
- Improve spinlock debugging a little.

* Wed Mar  2 2005 Dave Jones <davej redhat com>
- 2.6.11



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
if ( rpm_check( reference:"kernel-2.6.11-1.14_FC3", prefix:"kernel-", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kernel-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-0210", value:TRUE);
 set_kb_item(name:"CVE-2005-0384", value:TRUE);
 set_kb_item(name:"CVE-2005-0400", value:TRUE);
 set_kb_item(name:"CVE-2005-0449", value:TRUE);
 set_kb_item(name:"CVE-2005-0531", value:TRUE);
 set_kb_item(name:"CVE-2005-0736", value:TRUE);
 set_kb_item(name:"CVE-2005-0749", value:TRUE);
 set_kb_item(name:"CVE-2005-0750", value:TRUE);
 set_kb_item(name:"CVE-2005-0767", value:TRUE);
 set_kb_item(name:"CVE-2005-0815", value:TRUE);
}
