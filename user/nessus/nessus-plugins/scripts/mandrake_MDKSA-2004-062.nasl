#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:062
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14161);
 script_bugtraq_id(10352);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0535", "CVE-2004-0554");
 
 name["english"] = "MDKSA-2004:062: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:062 (kernel).


A vulnerability in the e1000 driver for the Linux kernel 2.4.26 and earlier was
discovered by Chris Wright. The e1000 driver does not properly reset memory or
restrict the maximum length of a data structure, which can allow a local user to
read portions of kernel memory (CVE-2004-0535).
A vulnerability was also discovered in the kernel were a certain C program would
trigger a floating point exception that would crash the kernel. This
vulnerability can only be triggered locally by users with shell access
(CVE-2004-0554).


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:062
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
if ( rpm_check( reference:"kernel-2.4.25.6mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-2.6.3.14mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.25.6mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.6.3.14mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.6.3.14mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.25.6mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.3.14mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.25-6mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.3-14mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6.3-14mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.21.0.31mdk-1-1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.4.21.0.31mdk-1-1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21.0.31mdk-1-1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-0.31mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.22.35mdk-1-1mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.22.35mdk-1-1mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.4.22.35mdk-1-1mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.22.35mdk-1-1mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.22-35mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK10.0")
 || rpm_exists(rpm:"kernel-", release:"MDK9.1")
 || rpm_exists(rpm:"kernel-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0535", value:TRUE);
 set_kb_item(name:"CVE-2004-0554", value:TRUE);
}
