#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:037
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14136);
 script_bugtraq_id(10211, 10221, 10233);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0229", "CVE-2004-0394", "CVE-2004-0424", "CVE-2004-0427");
 
 name["english"] = "MDKSA-2004:037: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:037 (kernel).


A vulnerability was found in the framebuffer driver of the 2.6 kernel. This is
due to incorrect use of the fb_copy_cmap function. (CVE-2004-0229)
A vulnerability has been found in the Linux kernel in the ip_setsockopt()
function code. There is an exploitable integer overflow inside the code handling
the MCAST_MSFILTER socket option in the IP_MSFILTER_SIZE macro calculation. This
issue is present in both 2.4 (2.4.25) and 2.6 kernels. (CVE-2004-0424)
There is a minor issue with the static buffer in 2.4 kernel's panic() function.
Although it's a possibly buffer overflow, it most like not exploitable due to
the nature of panic(). (CVE-2004-0394)
In do_fork(), if an error occurs after the mm_struct for the child has been
allocated, it is never freed. The exit_mm() meant to free it increments the
mm_count and this count is never decremented. (For a running process that is
exitting, schedule() takes care this; however, the child process being cleaned
up is not running.) In the CLONE_VM case, the parent's mm_struct will get an
extra mm_count and so it will never be freed. This issue is present in both 2.4
and 2.6 kernels. (CVE-2004-0427)
The provided packages are patched to fix these vulnerabilities. All users are
encouraged to upgrade to these updated kernels.
To update your kernel, please follow the directions located at:
http://www.mandrakesecure.net/en/kernelupdate.php


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:037
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
if ( rpm_check( reference:"kernel-2.4.25.4mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-2.6.3.9mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.25.4mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.6.3.9mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-i686-up-4GB-2.6.3.9mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-p3-smp-64GB-2.6.3.9mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.6.3.9mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.25.4mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.3.9mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.25-4mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.3-9mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6.3-9mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.21.0.30mdk-1-1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.4.21.0.30mdk-1-1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21.0.30mdk-1-1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-0.30mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.22.30mdk-1-1mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.22.30mdk-1-1mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.4.22.30mdk-1-1mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.22.30mdk-1-1mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.22-30mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK10.0")
 || rpm_exists(rpm:"kernel-", release:"MDK9.1")
 || rpm_exists(rpm:"kernel-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0229", value:TRUE);
 set_kb_item(name:"CVE-2004-0394", value:TRUE);
 set_kb_item(name:"CVE-2004-0424", value:TRUE);
 set_kb_item(name:"CVE-2004-0427", value:TRUE);
}
