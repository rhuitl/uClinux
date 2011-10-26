#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:107
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18584);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-1275", "CVE-2005-1739");
 
 name["english"] = "MDKSA-2005:107: ImageMagick";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:107 (ImageMagick).



A heap-based buffer overflow was found in the way that ImageMagick parses PNM
files. If an attacker can trick a victim into opening a specially crafted PNM
file, the attacker could execute arbitrary code on the victim's machine
(CVE-2005-1275).

As well, a Denial of Service vulnerability was found in the way that
ImageMagick parses XWD files. If a user or program executed ImageMagick to
process a malicious XWD file, ImageMagick will enter info an infinite loop
causing a DoS (CVE-2005-1739).

The updated packages have been patched to fix these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:107
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ImageMagick package";
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
if ( rpm_check( reference:"ImageMagick-6.0.4.4-5.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-doc-6.0.4.4-5.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libMagick6.4.0-6.0.4.4-5.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libMagick6.4.0-devel-6.0.4.4-5.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-Magick-6.0.4.4-5.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-6.2.0.3-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-doc-6.2.0.3-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libMagick8.0.2-6.2.0.3-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libMagick8.0.2-devel-6.2.0.3-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-Image-Magick-6.2.0.3-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ImageMagick-", release:"MDK10.1")
 || rpm_exists(rpm:"ImageMagick-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1275", value:TRUE);
 set_kb_item(name:"CVE-2005-1739", value:TRUE);
}
