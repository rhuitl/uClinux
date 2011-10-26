#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:003
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16307);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1235", "CVE-2005-0001");
 
 name["english"] = "SUSE-SA:2005:003: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:003 (kernel).



Several exploitable security problems were identified and fixed in
the Linux kernel, the core of every SUSE Linux product.


- Due to missing locking in the sys_uselib system call a local attacker
can gain root access. This was found by Paul Starzetz and is tracked
by the Mitre CVE ID CVE-2004-1235.


- Paul Starzetz also found a race condition in SMP page table handling
which could lead to a local attacker gaining root access on SMP
machines. This is tracked by the Mitre CVE ID CVE-2005-0001.


- A local denial of service was found in the auditing subsystem which
have lead a local attacker crashing the machine. This was reported
and fixed by Redhat.


- The sendmsg / cmsg fix from the previous kernel update was faulty
on 64bit systems with 32bit compatibility layer and could lead to
32bit applications not working correctly on those 64bit systems.


- The smbfs security fixes from a before-previous kernel update were
faulty for some file write cases.


- A local denial of service with Direct I/O access to NFS file systems
could lead a local attacker to crash a machine with NFS mounts.


- grsecurity reported a signed integer problem in the SCSI ioctl
handling which had a missing boundary check.
Due to C language specifics, this evaluation was not correct and
there actually is no problem in this code.
The signed / unsigned mismatch was fixed nevertheless.


- Several more small non security problems were fixed.


NOTE: Two days ago we released the Service Pack 1 for the SUSE Linux
Enterprise Server 9. This kernel update contains fixes for the SUSE
Linux Enterprise Server 9 GA version kernel line.

A fix for the Service Pack 1 version line will be available shortly.



Solution : http://www.suse.de/security/advisories/2005_03_kernel.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kernel package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kernel-source-2.4.21-273", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.21-273", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.21-273", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.21-273", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.21-273", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.20.SuSE-129", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.20-129", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.20-129", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.20-129", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.20-129", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-273", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.21-273", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.21-273", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.21-273", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp4G-2.4.21-273", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_um-2.4.21-273", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.5-7.111.30", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-2.6.5-7.111.30", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.5-7.111.30", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.5-7.111.30", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.8-24.11", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-2.6.8-24.11", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.8-24.11", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.8-24.11", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-um-2.6.8-24.11", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"SUSE8.1")
 || rpm_exists(rpm:"kernel-", release:"SUSE8.2")
 || rpm_exists(rpm:"kernel-", release:"SUSE9.0")
 || rpm_exists(rpm:"kernel-", release:"SUSE9.1")
 || rpm_exists(rpm:"kernel-", release:"SUSE9.2") )
{
 set_kb_item(name:"CVE-2004-1235", value:TRUE);
 set_kb_item(name:"CVE-2005-0001", value:TRUE);
}
