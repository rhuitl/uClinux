#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:112
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21769);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2006-2906");
 
 name["english"] = "MDKSA-2006:112: gd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:112 (gd).



The LZW decoding in the gdImageCreateFromGifPtr function in the Thomas

Boutell graphics draw (GD) library (aka libgd) 2.0.33 allows remote

attackers to cause a denial of service (CPU consumption) via malformed

GIF data that causes an infinite loop.



gd-2.0.15 in Corporate 3.0 is not affected by this issue.



Packages have been patched to correct this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:112
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gd package";
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
if ( rpm_check( reference:"gd-utils-2.0.33-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgd2-2.0.33-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgd2-devel-2.0.33-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgd2-static-devel-2.0.33-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gd-utils-2.0.33-3.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgd2-2.0.33-3.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgd2-devel-2.0.33-3.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgd2-static-devel-2.0.33-3.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gd-", release:"MDK10.2")
 || rpm_exists(rpm:"gd-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-2906", value:TRUE);
}
