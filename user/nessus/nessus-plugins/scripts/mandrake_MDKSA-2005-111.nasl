#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:111
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18599);
 script_version ("$Revision: 1.3 $");
# script_cve_id("CVE-2005-0109", "CVE-2005-0209", "CVE-2005-0384", "CVE-2005-0400", "CVE-2005-0530", "CVE-2005-0531", "CVE-2005-0749", "CVE-2005-0750", "CVE-2005-0767", "CVE-2005-1263");
 
 name["english"] = "MDKSA-2005:111: kernel-2.4";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:111 (kernel-2.4).

Multiple vulnerabilities in the Linux kernel have been discovered and fixed in
this update. 

Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:111
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kernel-2.4 package";
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
if ( rpm_check( reference:"kernel-2.4.25.14mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.25.14mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-i686-up-4GB-2.4.25.14mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-p3-smp-64GB-2.4.25.14mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.25.14mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.25-14mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.28.0.rc1.6mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.28.0.rc1.6mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-i586-up-1GB-2.4.28.0.rc1.6mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.28.0.rc1.6mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4-2.4.28-0.rc1.6mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kernel-2.4-", release:"MDK10.0")
 || rpm_exists(rpm:"kernel-2.4-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-0109", value:TRUE);
 set_kb_item(name:"CVE-2005-0209", value:TRUE);
 set_kb_item(name:"CVE-2005-0384", value:TRUE);
 set_kb_item(name:"CVE-2005-0400", value:TRUE);
 set_kb_item(name:"CVE-2005-0530", value:TRUE);
 set_kb_item(name:"CVE-2005-0531", value:TRUE);
 set_kb_item(name:"CVE-2005-0749", value:TRUE);
 set_kb_item(name:"CVE-2005-0750", value:TRUE);
 set_kb_item(name:"CVE-2005-0767", value:TRUE);
 set_kb_item(name:"CVE-2005-1263", value:TRUE);
}
