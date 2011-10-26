#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:112
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18649);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2005-2096");
 
 name["english"] = "MDKSA-2005:112: zlib";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:112 (zlib).



Tavis Ormandy of the Gentoo Security Project discovered a vulnerability in zlib
where a certain data stream would cause zlib to corrupt a data structure,
resulting in the linked application to dump core.

The updated packages have been patched to correct this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:112
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the zlib package";
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
if ( rpm_check( reference:"zlib1-1.2.1-2.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib1-devel-1.2.1-2.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib1-1.2.1.1-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib1-devel-1.2.1.1-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib1-1.2.2.2-2.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib1-devel-1.2.2.2-2.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"zlib-", release:"MDK10.0")
 || rpm_exists(rpm:"zlib-", release:"MDK10.1")
 || rpm_exists(rpm:"zlib-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2096", value:TRUE);
}
