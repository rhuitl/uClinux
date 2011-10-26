#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18324);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0210", "CVE-2005-0384", "CVE-2005-0400", "CVE-2005-0449", "CVE-2005-0531", "CVE-2005-0736", "CVE-2005-0749", "CVE-2005-0750", "CVE-2005-0767", "CVE-2005-0815");
 
 name["english"] = "Fedora Core 2 2005-262: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-262 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of
any
Linux operating system. The kernel handles the basic functions
of the operating system: memory allocation, process allocation, device
input and output, etc.


* Sun Mar 27 2005 Dave Jones
- Catch up with all recent security issues.
- CVE-2005-0210 : dst leak
- CVE-2005-0384 : ppp dos
- CVE-2005-0531 : Sign handling issues.
- CVE-2005-0400 : EXT2 information leak.
- CVE-2005-0449 : Remote oops.
- CVE-2005-0736 : Epoll overflow
- CVE-2005-0749 : ELF loader may kfree wrong memory.
- CVE-2005-0750 : Missing range checking in bluetooth
- CVE-2005-0767 : drm race in radeon
- CVE-2005-0815 : Corrupt isofs images could cause oops.

* Tue Mar 22 2005 Dave Jones
- Fix swapped parameters to memset in ieee802.11 code.



Solution : http://www.fedoranews.org/blog/index.php?p=531
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
if ( rpm_check( reference:"kernel-2.6.10-   Release : 1.771_FC2", prefix:"kernel-", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kernel-", release:"FC2") )
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
