#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:114-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21776);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0941", "CVE-2004-0990");
 
 name["english"] = "MDKSA-2006:114-1: libwmf";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:114-1 (libwmf).



Multiple buffer overflows in the gd graphics library (libgd) 2.0.21 and

earlier may allow remote attackers to execute arbitrary code via malformed

image files that trigger the overflows due to improper calls to the gdMalloc

function. (CVE-2004-0941)



Integer overflows were reported in the GD Graphics Library (libgd)

2.0.28, and possibly other versions. These overflows allow remote

attackers to cause a denial of service and possibly execute arbitrary

code via PNG image files with large image rows values that lead to a

heap-based buffer overflow in the gdImageCreateFromPngCtx() function.

Libwmf contains an embedded copy of the GD library code. (CVE-2004-0990)



Update:



The previous update incorrectly attributed the advisory text to

CVE-2004-0941, while it should have been CVE-2004-0990. Additional

review of the code found fixes for CVE-2004-0941 were missing and have

also been included in this update.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:114-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libwmf package";
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
if ( rpm_check( reference:"libwmf0.2_7-0.2.8.3-3.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwmf0.2_7-devel-0.2.8.3-3.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwmf-0.2.8.3-3.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwmf0.2_7-0.2.8.3-6.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwmf0.2_7-devel-0.2.8.3-6.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwmf-0.2.8.3-6.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"libwmf-", release:"MDK10.2")
 || rpm_exists(rpm:"libwmf-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2004-0941", value:TRUE);
 set_kb_item(name:"CVE-2004-0990", value:TRUE);
}
