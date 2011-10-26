#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:074
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14057);
 script_bugtraq_id(7791, 8042);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0001", "CVE-2003-0244", "CVE-2003-0246", "CVE-2003-0247", "CVE-2003-0248", "CVE-2003-0462");
 
 name["english"] = "MDKSA-2003:074: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:074 (kernel).


Multiple vulnerabilities were discovered and fixed in the Linux kernel.
* CVE-2003-0001: Multiple ethernet network card drivers do not pad frames with
null bytes which allows remote attackers to obtain information from previous
packets or kernel memory by using special malformed packets.
* CVE-2003-0244: The route cache implementation in the 2.4 kernel and the
Netfilter IP conntrack module allows remote attackers to cause a Denial of
Service (DoS) via CPU consumption due to packets with forged source addresses
that cause a large number of hash table collisions related to the PREROUTING
chain.
* CVE-2003-0246: The ioperm implementation in 2.4.20 and earlier kernels does
not properly restrict privileges, which allows local users to gain read or write
access to certain I/O ports.
* CVE-2003-0247: A vulnerability in the TTY layer of the 2.4 kernel allows
attackers to cause a kernel oops resulting in a DoS.
* CVE-2003-0248: The mxcsr code in the 2.4 kernel allows attackers to modify CPU
state registers via a malformed address.
* CVE-2003-0462: A file read race existed in the execve() system call.
Kernels for 9.1/x86 are also available (see MDKSA-2003:066).
MandrakeSoft encourages all users to upgrade to these new kernels.
For full instructions on how to properly upgrade your kernel, please review
http://www.mandrakesecure.net/en/docs/magic.php.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:074
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kernel package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kernel-2.4.19.35mdk-1-1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.19.35mdk-1-1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.19-35mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.19.35mdk-1-1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.4.19.35mdk-1-1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.19.35mdk-1-1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.19-35mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.19.35mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.19.35mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.19-35mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.19.35mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.4.19.35mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.19.35mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.19-35mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK8.2")
 || rpm_exists(rpm:"kernel-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0001", value:TRUE);
 set_kb_item(name:"CVE-2003-0244", value:TRUE);
 set_kb_item(name:"CVE-2003-0246", value:TRUE);
 set_kb_item(name:"CVE-2003-0247", value:TRUE);
 set_kb_item(name:"CVE-2003-0248", value:TRUE);
 set_kb_item(name:"CVE-2003-0462", value:TRUE);
}
