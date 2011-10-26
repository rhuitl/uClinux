#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:021
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17982);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0750");
 
 name["english"] = "SUSE-SA:2005:021: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:021 (kernel).


This Linux kernel security update fixes a problem within the Bluetooth
kernel stack which can be used by a local attacker to gain root access or
crash the machine.

To exploit this problem, the Bluetooth modules do not need to be
loaded since they are auto loaded on demand (except in products mentioned
below).

This problem has been assigned the Mitre CVE ID CVE-2005-0750.

Updated packages have been provided for the default affected products:
- SUSE Linux 8.2, 9.0 and 9.2 (both i386 and x86_64) - SUSE Linux
Enterprise Server 8 (i386, ia64 and x86_64) - SUSE Linux Desktop 1.0

Other architectures do not have Bluetooth enabled.
Also SUSE Linux 9.1, SUSE Linux Enterprise Server 9 and Novell Linux
Desktop 9 are not affected by default since the Bluetooth module is not
auto loaded. These will get the patch with the next security update.



Solution : http://www.suse.de/security/advisories/2005_21_kernel.html
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
if ( rpm_check( reference:"k_athlon-2.4.20-133", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.20-133", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.20-133", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.20-133", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.20.SuSE-133", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"Intel-536ep-4.62-24", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"Intel-v92ham-4.53-24", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.21-286", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.21-286", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.21-286", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp4G-2.4.21-286", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_um-2.4.21-286", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-286", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ltmodem-8.26a-213", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"Intel-536ep-4.69-5.7", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-2.6.8-24.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-nongpl-2.6.8-24.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.8-24.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-default-nongpl-2.6.8-24.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.8-24.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-nongpl-2.6.8-24.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.8-24.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.8-24.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-um-2.6.8-24.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-um-nongpl-2.6.8-24.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ltmodem-8.31a8-6.7", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"um-host-install-initrd-1.0-48.7", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"um-host-kernel-2.6.8-24.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-docs-2.6.8-24.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"SUSE8.2")
 || rpm_exists(rpm:"kernel-", release:"SUSE9.0")
 || rpm_exists(rpm:"kernel-", release:"SUSE9.2") )
{
 set_kb_item(name:"CVE-2005-0750", value:TRUE);
}
