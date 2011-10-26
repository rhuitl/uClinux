#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:110
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14092);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0961");
 
 name["english"] = "MDKSA-2003:110: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:110 (kernel).


A vulnerability was discovered in the Linux kernel versions 2.4.22 and previous.
A flaw in bounds checking in the do_brk() function can allow a local attacker to
gain root privileges. This vulnerability is known to be exploitable; an exploit
is in the wild at this time.
The Mandrake Linux 9.2 kernels are not vulnerable to this problem as the fix for
it is already present in kernel version 2.4.22-21mdk (provided in
MDKA-2003:021).
MandrakeSoft encourages all users to upgrade their systems immediately.
To upgrade your kernel, please use the documentation available online:
http://www.mandrakesecure.net/en/kernelupdate.php


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:110
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
if ( rpm_check( reference:"kernel-2.4.19.36mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.19.36mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.4.19.36mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.19.36mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.19-36mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.21.0.26mdk-1-1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.4.21.0.26mdk-1-1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21.0.26mdk-1-1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-0.26mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK9.0")
 || rpm_exists(rpm:"kernel-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0961", value:TRUE);
}
