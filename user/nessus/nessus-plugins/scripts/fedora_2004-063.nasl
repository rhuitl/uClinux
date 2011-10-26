#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13675);
 script_bugtraq_id(9429, 9570);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0001", "CVE-2004-0003");
 
 name["english"] = "Fedora Core 1 2004-063: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-063 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of your
Fedora Core Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.


* Mon Jan 26 2004 Dave Jones <davej@redhat.com>
- Fix error in wan config files that broke some configurators.
- Reenable VIA DRI.

* Fri Jan 16 2004 Dave Jones <davej@redhat.com>
- Merge VM updates from post 2.4.22
- Fix AMD64 ptrace security hole. (CVE-2004-0001)
- Fix NPTL SMP hang.
- Merge bits from 2.4.25pre
 - R128 DRI limits checking. (CVE-2004-0003)
 - Various ymfpci fixes.
 - tmpfs readdir does not update dir atime
 - Minor IPV4/Netfilter changes.
 - Fix userspace dereferencing bug in USB Vicam driver.
- Merge a few more bits from 2.4.23pre
 - Numerous tmpfs fixes.
 - Use list_add_tail in buffer_insert_list
 - Correctly dequeue SIGSTOP signals in kupdated
- Update laptop-mode patch to match mainline.

* Wed Jan 14 2004 Dave Jones <davej@redhat.com>
- Merge a few more missing netfilter fixes from upstream.

* Tue Jan 13 2004 Dave Jones <davej@redhat.com>
- Reenable Tux.
- Lots of updates from the 2.4.23 era.

* Mon Jan 12 2004 Dave Jones <davej@redhat.com>
- Avoid deadlocks in USB storage.

* Fri Jan 09 2004 Dave Jones <davej@redhat.com>
- Fix thread creation race.

* Thu Jan 08 2004 Dave Jones <davej@redhat.com>
- USB storage: Make Pentax Optio S4 work
- Config file tweaking. Only enable CONFIG_SIBLINGS_2
 on the kernels that need it.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-063.shtml
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
if ( rpm_check( reference:"kernel-2.4.22-1.2166.nptl", prefix:"kernel-", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kernel-", release:"FC1") )
{
 set_kb_item(name:"CVE-2004-0001", value:TRUE);
 set_kb_item(name:"CVE-2004-0003", value:TRUE);
}
