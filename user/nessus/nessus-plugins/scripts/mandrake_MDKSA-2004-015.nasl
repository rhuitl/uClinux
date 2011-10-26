#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:015
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14115);
 script_bugtraq_id(9570, 9691);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0003", "CVE-2004-0010", "CVE-2004-0075", "CVE-2004-0077");
 
 name["english"] = "MDKSA-2004:015: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:015 (kernel).


Paul Staretz discovered a flaw in return value checking in the mremap() function
in the Linux kernel, versions 2.4.24 and previous that could allow a local user
to obtain root privileges.
A vulnerability was found in the R128 DRI driver by Alan Cox. This could allow
local privilege escalation.
A flaw in the ncp_lookup() function in the ncpfs code (which is used to mount
NetWare volumes or print to NetWare printers) was found by Arjen van de Ven that
could allow local privilege escalation.
The Vicam USB driver in Linux kernel versions prior to 2.4.25 does not use the
copy_from_user function to access userspace, which crosses security boundaries.
This problem does not affect the Mandrake Linux 9.2 kernel.
Additionally, a ptrace hole that only affects the amd64/x86_64 platform has been
corrected.
The provided packages are patched to fix these vulnerabilities. All users are
encouraged to upgrade to these updated kernels.
To update your kernel, please follow the directions located at:
http://www.mandrakesecure.net/en/kernelupdate.php


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:015
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
if ( rpm_check( reference:"kernel-2.4.19.38mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.19.38mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.4.19.38mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.19.38mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.19-38mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.21.0.28mdk-1-1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.4.21.0.28mdk-1-1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21.0.28mdk-1-1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-0.28mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.22.28mdk-1-1mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.22.28mdk-1-1mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.4.22.28mdk-1-1mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.22.28mdk-1-1mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.22-28mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK9.0")
 || rpm_exists(rpm:"kernel-", release:"MDK9.1")
 || rpm_exists(rpm:"kernel-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0003", value:TRUE);
 set_kb_item(name:"CVE-2004-0010", value:TRUE);
 set_kb_item(name:"CVE-2004-0075", value:TRUE);
 set_kb_item(name:"CVE-2004-0077", value:TRUE);
}
