#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16166);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0001");
 
 name["english"] = "Fedora Core 3 2005-025: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-025 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of
any
Linux operating system. The kernel handles the basic functions
of the operating system: memory allocation, process allocation, device
input and output, etc.

CVE-2005-0001
Paul Starzetz from isec.pl found an exploitable hole in the x86
SMP page fault handler which could lead to privilege escalation.
http://www.isec.pl/vulnerabilities/isec-0022-pagefault.txt

This update additionally fixes a random memory corruption issue
present in the previous update, and in addition updates to the
latest -ac collection of patches. A full changelog
of the update vs the previous -ac8 based release is available
at http://lkml.org/lkml/2005/1/13/219


* Thu Jan 13 2005 Dave Jones
- Update to 2.6.10-ac9
- Fix slab corruption in ACPI video code.

* Mon Jan 10 2005 Dave Jones
- Add another Lexar card reader to the whitelist. (#143600)
- Package asm-m68k for asm-ppc includes. (don't ask). (#144604)



Solution : http://www.fedoranews.org/blog/index.php?p=278
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
if ( rpm_check( reference:"kernel-2.6.10-   Release : 1.741_FC3", prefix:"kernel-", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kernel-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-0001", value:TRUE);
}
