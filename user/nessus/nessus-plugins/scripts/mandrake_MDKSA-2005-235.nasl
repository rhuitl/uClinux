#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:235
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20466);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2490", "CVE-2005-2492", "CVE-2005-2873", "CVE-2005-3044", "CVE-2005-3055", "CVE-2005-3179", "CVE-2005-3180", "CVE-2005-3181", "CVE-2005-3257", "CVE-2005-3274");
 
 name["english"] = "MDKSA-2005:235: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:235 (kernel).



Multiple vulnerabilities in the Linux 2.6 kernel have been discovered and
corrected in this update: A stack-based buffer overflow in the sendmsg function
call in versions prior to 2.6.13.1 allow local users to execute arbitrary code
by calling sendmsg and modifying the message contents in another thread
(CVE-2005-2490). The raw_sendmsg function in versions prior to 2.6.13.1 allow
local users to cause a DoS (change hardware state) or read from arbitrary
memory via crafted input (CVE-2005-2492). The ipt_recent module in versions
prior to 2.6.12 does not properly perform certain tests when the jiffies value
is greater than LONG_MAX, which can cause ipt_recent netfilter rules to block
too early (CVE-2005-2873). Multiple vulnerabilities in versions prior to
2.6.13.2 allow local users to cause a DoS (oops from null dereference) via fput
in a 32bit ioctl on 64-bit x86 systems or sockfd_put in the 32-bit
routing_ioctl function on 64-bit systems (CVE-2005-3044). Versions 2.6.8 to
2.6.14-rc2 allow local users to cause a DoS (oops) via a userspace process that
issues a USB Request Block (URB) to a USB device and terminates before the URB
is finished, which leads to a stale pointer reference (CVE-2005-3055). drm.c in
version 2.6.13 and earlier creates a debug file in sysfs with world-readable
and world-writable permissions, allowing local users to enable DRM debugging
and obtain sensitive information (CVE-2005-3179). The Orinoco driver in 2.6.13
and earlier does not properly clear memory from a previously used packet whose
length is increased, allowing remote attackers to obtain sensitive information
(CVE-2005-3180). Kernels 2.6.13 and earlier, when CONFIG_AUDITSYSCALL is
enabled, use an incorrect function to free names_cache memory, preventing the
memory from being tracked by AUDITSYSCALL code and leading to a memory leak
(CVE-2005-3181). The VT implementation in version 2.6.12 allows local users to
use certain IOCTLs on terminals of other users and gain privileges
(CVE-2005-3257). A race condition in ip_vs_conn_flush in versions prior to
2.6.13, when running on SMP systems, allows local users to cause a DoS (null
dereference) by causing a connection timer to expire while the connection table
is being flushed before the appropriate lock is acquired (CVE-2005-3274). The
provided packages are patched to fix these vulnerabilities. All users are
encouraged to upgrade to these updated kernels. To update your kernel, please
follow the directions located at: http://www.mandriva.com/en/security/
kernelupdate



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:235
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
if ( rpm_check( reference:"kernel-2.6.12.14mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-i586-up-1GB-2.6.12.14mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-i686-up-4GB-2.6.12.14mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.12.14mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6-2.6.12-14mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6-2.6.12-14mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-xbox-2.6.12.14mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-xen0-2.6.12.14mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.12.14mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-2490", value:TRUE);
 set_kb_item(name:"CVE-2005-2492", value:TRUE);
 set_kb_item(name:"CVE-2005-2873", value:TRUE);
 set_kb_item(name:"CVE-2005-3044", value:TRUE);
 set_kb_item(name:"CVE-2005-3055", value:TRUE);
 set_kb_item(name:"CVE-2005-3179", value:TRUE);
 set_kb_item(name:"CVE-2005-3180", value:TRUE);
 set_kb_item(name:"CVE-2005-3181", value:TRUE);
 set_kb_item(name:"CVE-2005-3257", value:TRUE);
 set_kb_item(name:"CVE-2005-3274", value:TRUE);
}
