#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:040
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20939);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2973", "CVE-2005-3356", "CVE-2005-4605", "CVE-2005-4618", "CVE-2005-4639", "CVE-2006-0095", "CVE-2006-0454");
 
 name["english"] = "MDKSA-2006:040: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:040 (kernel).



A number of vulnerabilities were discovered and corrected in the Linux 2.6
kernel: The udp_v6_get_port function in udp.c, when running IPv6, allows local
users to cause a Denial of Service (infinite loop and crash) (CVE-2005-2973).
The mq_open system call in certain situations can decrement a counter twice as
a result of multiple calls to the mntput function when the dentry_open function
call fails, allowing a local user to cause a DoS (panic) via unspecified attack
vectors (CVE-2005-3356). The procfs code allows attackers to read sensitive
kernel memory via unspecified vectors in which a signed value is added to an
unsigned value (CVE-2005-4605). A buffer overflow in sysctl allows local users
to cause a DoS and possibly execute arbitrary code via a long string, which
causes sysctl to write a zero byte outside the buffer (CVE-2005-4618). A buffer
overflow in the CA-driver for TwinHan DST Frontend/Card allows local users to
cause a DoS (crash) and possibly execute arbitrary code by reading more than
eight bytes into an eight byte long array (CVE-2005-4639). dm-crypt does not
clear a structure before it is freed, which leads to a memory disclosure that
could allow local users to obtain sensitive information about a cryptographic
key (CVE-2006-0095). Remote attackers can cause a DoS via unknown attack
vectors related to an 'extra dst release when ip_options_echo fails' in icmp.c
(CVE-2006-0454). In addition to these security fixes, other fixes have been
included such as: - support for mptsas - fix for IPv6 with sis190 - a problem
with the time progressing twice as fast - a fix for Audigy 2 ZS Video Editor
sample rates - a fix for a supermount crash when accessing a supermount-ed CD/
DVD drive - a fix for improperly unloading sbp2 module The provided packages
are patched to fix these vulnerabilities. All users are encouraged to upgrade
to these updated kernels. To update your kernel, please follow the directions
located at: http://www.mandriva.com/en/security/kernelupdate



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:040
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
if ( rpm_check( reference:"kernel-2.6.12.17mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-i586-up-1GB-2.6.12.17mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-i686-up-4GB-2.6.12.17mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.12.17mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6-2.6.12-17mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6-2.6.12-17mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-xbox-2.6.12.17mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-xen0-2.6.12.17mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.12.17mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-2973", value:TRUE);
 set_kb_item(name:"CVE-2005-3356", value:TRUE);
 set_kb_item(name:"CVE-2005-4605", value:TRUE);
 set_kb_item(name:"CVE-2005-4618", value:TRUE);
 set_kb_item(name:"CVE-2005-4639", value:TRUE);
 set_kb_item(name:"CVE-2006-0095", value:TRUE);
 set_kb_item(name:"CVE-2006-0454", value:TRUE);
}
