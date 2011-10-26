#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:167
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19922);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2876");
 
 name["english"] = "MDKSA-2005:167: util-linux";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:167 (util-linux).



David Watson disovered that the umount utility, when using the '-r' cpmmand,
could remove some restrictive mount options such as 'nosuid'. IF /etc/fstab
contained user-mountable removable devices that specified nosuid, a local
attacker could exploit this flaw to execute arbitrary programs with root
privileges by calling 'umount -r' on a removable device.

The updated packages have been patched to ensure that '-r' can only be called
by the root user.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:167
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the util-linux package";
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
if ( rpm_check( reference:"losetup-2.12-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mount-2.12-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"util-linux-2.12-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"losetup-2.12a-5.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mount-2.12a-5.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"util-linux-2.12a-5.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"losetup-2.12a-12.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mount-2.12a-12.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"util-linux-2.12a-12.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"util-linux-", release:"MDK10.0")
 || rpm_exists(rpm:"util-linux-", release:"MDK10.1")
 || rpm_exists(rpm:"util-linux-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2876", value:TRUE);
}
