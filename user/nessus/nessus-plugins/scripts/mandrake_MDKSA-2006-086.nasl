#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:086
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21575);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0744", "CVE-2006-1052", "CVE-2006-1242", "CVE-2006-1522", "CVE-2006-1525", "CVE-2006-1527", "CVE-2006-2071", "CVE-2006-2271", "CVE-2006-2272");
 
 name["english"] = "MDKSA-2006:086: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:086 (kernel).


A number of vulnerabilities were discovered and corrected in the Linux
2.6 kernel.

Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:086
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
if ( rpm_check( reference:"bootsplash-3.1.12-0.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-2.6.12.21mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.6.12.21mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-i586-up-1GB-2.6.12.21mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-i686-up-4GB-2.6.12.21mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.12.21mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6-2.6.12-21mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6-2.6.12-21mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-xbox-2.6.12.21mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-xen0-2.6.12.21mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.12.21mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mkinitrd-4.2.17-17.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-0744", value:TRUE);
 set_kb_item(name:"CVE-2006-1052", value:TRUE);
 set_kb_item(name:"CVE-2006-1242", value:TRUE);
 set_kb_item(name:"CVE-2006-1522", value:TRUE);
 set_kb_item(name:"CVE-2006-1525", value:TRUE);
 set_kb_item(name:"CVE-2006-1527", value:TRUE);
 set_kb_item(name:"CVE-2006-2071", value:TRUE);
 set_kb_item(name:"CVE-2006-2271", value:TRUE);
 set_kb_item(name:"CVE-2006-2272", value:TRUE);
}
