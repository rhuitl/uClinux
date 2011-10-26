#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SuSE-SA:2004:005
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13823);
 script_bugtraq_id(9570, 9690, 9691);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2004-0003", "CVE-2004-0010", "CVE-2004-0075", "CVE-2004-0077");
 
 name["english"] = "SuSE-SA:2004:005: Linux Kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SuSE-SA:2004:005 (Linux Kernel).


Another bug in the Kernel's do_mremap() function, which is unrelated to
the bug fixed in SuSE-SA:2004:001, was found by Paul Starzetz.
The do_mremap() function of the Linux Kernel is used to manage
Virtual Memory Areas (VMAs) which includes moving, removing and
resizing of memory areas.  To remove old memory areas do_mremap()
uses the function du_munmap() without checking the return value.
By forcing do_munmap() to return an error the memory management of
a process can be tricked into moving page table entries from one VMA
to another. The destination VMA may be protected by a different ACL
which enables a local attacker to gain write access to previous read-only
pages.
The result will be local root access to the system.

Additionally to the bug mentioned above some other bugs were fixed
(depending on architecture) that can cause local denial-of-service
conditions:
- Vicam USB driver: CVE-2004-0075
+ denial-of-service due to problem while
copying data from user to kernel space
- Direct Render Infrastructure: CVE-2004-0003
+ denial-of-service due to integer overflow
+ needs r128 card and console to be exploited
- ncpfs/ncp_lookup: CVE-2004-0010
+ buffer overflow with the probability to
gain root
- execve():
+ malformed elf binaries can lead to a local
denial-of-service attack




Solution : http://www.suse.de/security/2004_05_linux_kernel.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the Linux Kernel package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"k_deflt-2.4.21-189", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.21-189", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.21-189", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.21-189", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-189", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.20-105", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.20-105", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.20-105", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.20-105", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.20.SuSE-104", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.21-192", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.21-192", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp4G-2.4.21-192", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_um-2.4.21-192", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.21-192", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-192", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"Linux Kernel-", release:"SUSE8.1")
 || rpm_exists(rpm:"Linux Kernel-", release:"SUSE8.2")
 || rpm_exists(rpm:"Linux Kernel-", release:"SUSE9.0") )
{
 set_kb_item(name:"CVE-2004-0003", value:TRUE);
 set_kb_item(name:"CVE-2004-0010", value:TRUE);
 set_kb_item(name:"CVE-2004-0075", value:TRUE);
 set_kb_item(name:"CVE-2004-0077", value:TRUE);
}
