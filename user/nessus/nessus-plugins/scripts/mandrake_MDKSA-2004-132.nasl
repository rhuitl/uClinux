#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:132
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15737);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0990");
 
 name["english"] = "MDKSA-2004:132: gd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:132 (gd).



Integer overflows were reported in the GD Graphics Library (libgd) 2.0.28, and
possibly other versions. These overflows allow remote attackers to cause a
denial of service and possibly execute arbitrary code via PNG image files with
large image rows values that lead to a heap-based buffer overflow in the
gdImageCreateFromPngCtx() function.

The updated packages have been patched to prevent these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:132
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gd package";
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
if ( rpm_check( reference:"libgd2-2.0.15-4.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgd2-devel-2.0.15-4.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgd2-static-devel-2.0.15-4.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gd-utils-2.0.15-4.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgd2-2.0.27-3.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgd2-devel-2.0.27-3.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgd2-static-devel-2.0.27-3.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gd-utils-2.0.27-3.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgd2-2.0.15-3.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgd2-devel-2.0.15-3.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgd2-static-devel-2.0.15-3.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gd-utils-2.0.15-3.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gd-", release:"MDK10.0")
 || rpm_exists(rpm:"gd-", release:"MDK10.1")
 || rpm_exists(rpm:"gd-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0990", value:TRUE);
}
