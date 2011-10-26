#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18377);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1263", "CVE-2005-1264", "CVE-2005-1368", "CVE-2005-1369");
 
 name["english"] = "Fedora Core 3 2005-392: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-392 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of
any
Linux operating system. The kernel handles the basic functions
of the operating system: memory allocation, process allocation, device
input and output, etc.


* Tue May 17 2005 Dave Jones
- Remove the unused (and outdated) Xen patches from the FC3 tree.

* Mon May 16 2005 Dave Jones
- Rebase to 2.6.11.10, (fixing CVE-2005-1264)

* Thu May 12 2005 Dave Jones
- Rebase to 2.6.11.9, (fixing CVE-2005-1263)

* Tue May 10 2005 Dave Jones
- Fix two bugs in x86-64 page fault handler.

* Mon May 9 2005 Dave Jones
- Rebase to 2.6.11.8
| Fixes CVE-2005-1368 (local DoS in key lookup). (#156680)
| Fixes CVE-2005-1369 (i2c alarms sysfs DoS). (#156683)
- Merge IDE fixes from 2.6.11-ac7
- Add Conflicts for older IPW firmwares.
- Fix conntrack leak with raw sockets.

* Sun May 1 2005 Dave Jones
- Various firewire fixes backported from -mm. (#133798)
(Thanks to Jody McIntyre for doing this)

* Fri Apr 29 2005 Dave Jones
- fix oops in aacraid open when using adaptec tools. (#148761)
- Blacklist another brainless SCSI scanner. (#155457)

* Thu Apr 21 2005 Dave Jones
- Fix up SCSI queue locking. (#155472)

* Tue Apr 19 2005 Dave Jones
- SCSI tape security: require CAP_ADMIN for SG_IO etc. (#155355)

* Mon Apr 18 2005 Dave Jones
- Retry more aggressively during USB device initialization

* Thu Apr 14 2005 Dave Jones
- Build DRM modular. (#154769)

* Fri Apr 8 2005 Dave Jones
- Disable Longhaul driver (again).



Solution : http://www.fedoranews.org/blog/index.php?p=695
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
if ( rpm_check( reference:"kernel-2.6.11-   Release : 1.27_FC3", prefix:"kernel-", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kernel-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-1263", value:TRUE);
 set_kb_item(name:"CVE-2005-1264", value:TRUE);
 set_kb_item(name:"CVE-2005-1368", value:TRUE);
 set_kb_item(name:"CVE-2005-1369", value:TRUE);
}
