#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:022
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16259);
 script_version ("$Revision: 1.3 $");
 if (NASL_LEVEL >= 2191) script_cve_id("CVE-2004-0814", "CVE-2004-0816", "CVE-2004-0883", "CVE-2004-0949", "CVE-2004-1016", "CVE-2004-1058", "CVE-2004-1068", "CVE-2004-1069", "CVE-2004-1070", "CVE-2004-1071", "CVE-2004-1072", "CVE-2004-1073", "CVE-2004-1074", "CVE-2004-1137", "CVE-2004-1151", "CVE-2004-1235", "CVE-2005-0001", "CVE-2005-0003");
 
 name["english"] = "MDKSA-2005:022: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:022 (kernel).


A number of vulnerabilities are fixed in the 2.4 and 2.6 kernels with this
advisory.


To update your kernel, please follow the directions located at:

http://wwwnew.mandriva.com/security/kernelupdate

PLEASE NOTE: Mandrakelinux 10.0 users will need to upgrade to the latest
module-init-tools package prior to upgrading their kernel. Likewise, MNF8.2
users will need to upgrade to the latest modutils package prior to upgrading
their kernel.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:022
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kernel package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kernel-2.4.25.13mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-2.6.3.25mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.25.13mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.6.3.25mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-i686-up-4GB-2.4.25.13mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-i686-up-4GB-2.6.3.25mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-p3-smp-64GB-2.4.25.13mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-p3-smp-64GB-2.6.3.25mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.6.3.25mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.25.13mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.3.25mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.25-13mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.3-25mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6.3-25mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"module-init-tools-3.0-1.2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.28.0.rc1.5mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-2.6.8.1.24mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.28.0.rc1.5mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.6.8.1.24mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-i586-up-1GB-2.4.28.0.rc1.5mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-i586-up-1GB-2.6.8.1.24mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-i686-up-64GB-2.6.8.1.24mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.6.8.1.24mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.28.0.rc1.5mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.8.1.24mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4-2.4.28-0.rc1.5mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6-2.6.8.1-24mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6-2.6.8.1-24mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.22.41mdk-1-1mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.22.41mdk-1-1mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-i686-up-4GB-2.4.22.41mdk-1-1mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-p3-smp-64GB-2.4.22.41mdk-1-1mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.4.22.41mdk-1-1mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.22.41mdk-1-1mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.22-41mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK10.0")
 || rpm_exists(rpm:"kernel-", release:"MDK10.1")
 || rpm_exists(rpm:"kernel-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0814", value:TRUE);
 set_kb_item(name:"CVE-2004-0816", value:TRUE);
 set_kb_item(name:"CVE-2004-0883", value:TRUE);
 set_kb_item(name:"CVE-2004-0949", value:TRUE);
 set_kb_item(name:"CVE-2004-1016", value:TRUE);
 set_kb_item(name:"CVE-2004-1058", value:TRUE);
 set_kb_item(name:"CVE-2004-1068", value:TRUE);
 set_kb_item(name:"CVE-2004-1069", value:TRUE);
 set_kb_item(name:"CVE-2004-1070", value:TRUE);
 set_kb_item(name:"CVE-2004-1071", value:TRUE);
 set_kb_item(name:"CVE-2004-1072", value:TRUE);
 set_kb_item(name:"CVE-2004-1073", value:TRUE);
 set_kb_item(name:"CVE-2004-1074", value:TRUE);
 set_kb_item(name:"CVE-2004-1137", value:TRUE);
 set_kb_item(name:"CVE-2004-1151", value:TRUE);
 set_kb_item(name:"CVE-2004-1235", value:TRUE);
 set_kb_item(name:"CVE-2005-0001", value:TRUE);
 set_kb_item(name:"CVE-2005-0003", value:TRUE);
}
