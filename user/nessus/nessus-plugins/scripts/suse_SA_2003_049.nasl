#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SuSE-SA:2003:049
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13817);
 script_bugtraq_id(9138);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0961");
 
 name["english"] = "SuSE-SA:2003:049: Linux Kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SuSE-SA:2003:049 (Linux Kernel).


This security update fixes a serious vulnerability in the Linux
kernel.  A missing bounds check in the brk() system call allowed
processes to request memory beyond the maximum size allowed for tasks,
causing kernel memory to be mapped into the process' address space.
This allowed local attackers to obtain super user privileges.

An exploit for this vulnerability is circulating in the wild, and
has been used to compromise OpenSource development servers.

There is no temporary workaround for this bug.

This update also fixes several other security issues in the
kernel

-	race condition with files opened via O_DIRECT which could
be exploited to read disk blocks randomly. This could include
blocks of previously deleted files with sensitive content.
-	don't allow users to send signals to kmod
-	when reading the RTC, don't leak kernel stack data to user space



Solution : http://www.suse.de/security/2003_049_kernel.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the Linux Kernel package";
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
if ( rpm_check( reference:"k_deflt-2.4.18-281", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.18-281", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.18-281", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_i386-2.4.18-281", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.18.SuSE-281", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.18-281", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.18-281", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.18-281", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_i386-2.4.18-281", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.18.SuSE-281", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.21-151", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.21-151", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.21-151", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.21-151", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-151", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.20-101", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.20-101", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.20-101", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.20-101", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.20.SuSE-101", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.21-144", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.21-144", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.21-144", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-144", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"Linux Kernel-", release:"SUSE7.3")
 || rpm_exists(rpm:"Linux Kernel-", release:"SUSE8.0")
 || rpm_exists(rpm:"Linux Kernel-", release:"SUSE8.1")
 || rpm_exists(rpm:"Linux Kernel-", release:"SUSE8.2")
 || rpm_exists(rpm:"Linux Kernel-", release:"SUSE9.0") )
{
 set_kb_item(name:"CVE-2003-0961", value:TRUE);
}
