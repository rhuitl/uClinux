#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:020
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13836);
 script_bugtraq_id(10352, 10566, 10779);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2004-0495", "CVE-2004-0496", "CVE-2004-0497", "CVE-2004-0535", "CVE-2004-0626");
 
 name["english"] = "SUSE-SA:2004:020: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2004:020 (kernel).


Multiple security vulnerabilities are being addressed with this security
update of the Linux kernel.

Kernel memory access vulnerabilities are fixed in the e1000, decnet, 
acpi_asus, alsa, airo/WLAN, pss and mpu401 drivers. These 
vulnerabilities can lead to kernel memory read access, write access 
and local denial of service conditions, resulting in access to the 
root account for an attacker with a local account on the affected 
system.

Missing Discretionary Access Control (DAC) checks in the chown(2) system
call allow an attacker with a local account to change the group
ownership of arbitrary files, which leads to root privileges on affected
systems. It is specific to kernel version 2.6 based systems such as 
the SUSE Linux 9.1 product, that only local shell access is needed to 
exploit this vulnerability. An interesting variant of the missing 
checks is that the ownership of files in the /proc filesystem can be 
altered, while the changed ownership still does not allow the files to 
be accessed as a non-root user for to be able to exploit the 
vulnerability. Systems that are based on a version 2.4 kernel are not 
vulnerable to the /proc weakness, and exploitation of the weakness 
requires the use of the kernel NFS server (knfsd). If the knfsd NFS 
server is not activated (it is off by default), the vulnerability is 
not exposed. These issues related to the chown(2) system call have been 
discovered by Michael Schroeder and Ruediger Oertel, both SUSE LINUX.

The only network-related vulnerability fixed with the kernel updates
that are subject to this announcement affect the SUSE Linux 9.1 
distribution only, as it is based on a 2.6 kernel. Found and reported 
to bugtraq by Adam Osuchowski and Tomasz Dubinski, the vulnerability 
allows a remote attacker to send a specially crafted TCP packet to a 
vulnerable system, causing that system to stall if it makes use of 
TCP option matching netfilter rules.

In some rare configurations of the SUSE Linux 9.1 distribution, some 
users have experienced stalling systems during system startup. These 
problems are fixed with this kernel update.




Solution : http://www.suse.de/security/2004_20_kernel.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kernel package";
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
if ( rpm_check( reference:"k_deflt-2.4.18-303", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.18-303", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.18-303", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_i386-2.4.18-303", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.18.SuSE-303", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.21-231", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.21-231", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.21-231", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.21-231", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-231", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.20-115", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.20-115", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.20-115", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.20-115", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.20.SuSE-115", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.21-231", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.21-231", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.21-231", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp4G-2.4.21-231", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_um-2.4.21-231", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-231", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.5-7.95", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.5-7.95", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-2.6.5-7.95", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-2.6.5-7.95", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.5-7.95", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"SUSE8.0")
 || rpm_exists(rpm:"kernel-", release:"SUSE8.1")
 || rpm_exists(rpm:"kernel-", release:"SUSE8.2")
 || rpm_exists(rpm:"kernel-", release:"SUSE9.0")
 || rpm_exists(rpm:"kernel-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0495", value:TRUE);
 set_kb_item(name:"CVE-2004-0496", value:TRUE);
 set_kb_item(name:"CVE-2004-0497", value:TRUE);
 set_kb_item(name:"CVE-2004-0535", value:TRUE);
 set_kb_item(name:"CVE-2004-0626", value:TRUE);
}
