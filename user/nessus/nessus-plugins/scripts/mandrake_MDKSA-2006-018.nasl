#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:018
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20796);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3527", "CVE-2005-3783", "CVE-2005-3784", "CVE-2005-3805", "CVE-2005-3806", "CVE-2005-3808");
 
 name["english"] = "MDKSA-2006:018: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:018 (kernel).



A number of vulnerabilites have been corrected in the Linux kernel: A race
condition in the 2.6 kernel could allow a local user to cause a DoS by
triggering a core dump in one thread while another thread has a pending SIGSTOP
(CVE-2005-3527). The ptrace functionality in 2.6 kernels prior to 2.6.14.2,
using CLONE_THREAD, does not use the thread group ID to check whether it is
attaching to itself, which could allow local users to cause a DoS
(CVE-2005-3783). The auto-reap child process in 2.6 kernels prior to 2.6.15
include processes with ptrace attached, which leads to a dangling ptrace
reference and allows local users to cause a crash (CVE-2005-3784). A locking
problem in the POSIX timer cleanup handling on exit on kernels 2.6.10 to 2.6.14
when running on SMP systems, allows a local user to cause a deadlock involving
process CPU timers (CVE-2005-3805). The IPv6 flowlabel handling code in 2.4 and
2.6 kernels prior to 2.4.32 and 2.6.14 modifes the wrong variable in certain
circumstances, which allows local users to corrupt kernel memory or cause a
crash by triggering a free of non-allocated memory (CVE-2005-3806). An integer
overflow in 2.6.14 and earlier could allow a local user to cause a hang via
64-bit mmap calls that are not properly handled on a 32-bit system
(CVE-2005-3808). As well, other bugfixes are included in this update: Fixes to
swsup and HDA sound fixes (DMA buffer fixes, and fixes for the AD1986a codec,
added support for Nvidia chipsets, and new model information for the Gigabyte
K8N51). MCP51 forcedeth support has been added.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:018
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kernel package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kernel-2.6.12.15mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-i586-up-1GB-2.6.12.15mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-i686-up-4GB-2.6.12.15mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.12.15mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6-2.6.12-15mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6-2.6.12-15mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-xbox-2.6.12.15mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-xen0-2.6.12.15mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.12.15mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3527", value:TRUE);
 set_kb_item(name:"CVE-2005-3783", value:TRUE);
 set_kb_item(name:"CVE-2005-3784", value:TRUE);
 set_kb_item(name:"CVE-2005-3805", value:TRUE);
 set_kb_item(name:"CVE-2005-3806", value:TRUE);
 set_kb_item(name:"CVE-2005-3808", value:TRUE);
}
