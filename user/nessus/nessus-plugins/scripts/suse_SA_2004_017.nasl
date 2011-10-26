#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SuSE-SA:2004:017
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13833);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0554");
 
 name["english"] = "SuSE-SA:2004:017: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SuSE-SA:2004:017 (kernel).


The Linux kernel is vulnerable to a local denial-of-service attack.
By using a C program it is possible to trigger a floating point
exception that puts the kernel into an unusable state.
To execute this attack a malicious user needs shell access to the
victim's machine.
The severity of this bug is considered low because local denial-of-
service attacks are hard to prevent in general.
Additionally the bug is limited to x86 and x86_64 architecture.




Solution : http://www.suse.de/security/2004_17_kernel.html
Risk factor : Medium";



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
if ( rpm_check( reference:"kernel-source-2.4.18.SuSE-299", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.18-299", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.18-299", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.18-299", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_i386-2.4.18-299", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-226", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.21-226", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.21-226", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.21-226", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.21-226", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.20.SuSE-113", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.20-113", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.20-113", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.20-113", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.20-113", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-226", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.21-226", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.21-226", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.21-226", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp4G-2.4.21-226", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_um-2.4.21-226", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.5-7.75", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.5-7.75", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.5-7.75", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-2.6.5-7.75", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"SUSE8.0")
 || rpm_exists(rpm:"kernel-", release:"SUSE8.1")
 || rpm_exists(rpm:"kernel-", release:"SUSE8.2")
 || rpm_exists(rpm:"kernel-", release:"SUSE9.0")
 || rpm_exists(rpm:"kernel-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0554", value:TRUE);
}
