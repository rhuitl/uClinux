#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:024
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20818);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-0397", "CVE-2005-4601", "CVE-2006-0082");
 
 name["english"] = "MDKSA-2006:024: ImageMagick";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:024 (ImageMagick).



The delegate code in ImageMagick 6.2.4.x allows remote attackers to execute
arbitrary commands via shell metacharacters in a filename that is processed by
the display command. (CVE-2005-4601) A format string vulnerability in the
SetImageInfo function in image.c for ImageMagick 6.2.3, and other versions,
allows user-complicit attackers to cause a denial of service (crash) and
possibly execute arbitrary code via a numeric format string specifier such as
%d in the file name, a variant of CVE-2005-0397, and as demonstrated using the
convert program. (CVE-2006-0082) The updated packages have been patched to
correct these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:024
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ImageMagick package";
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
if ( rpm_check( reference:"ImageMagick-6.2.4.3-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-doc-6.2.4.3-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libMagick8.4.2-6.2.4.3-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libMagick8.4.2-devel-6.2.4.3-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-Image-Magick-6.2.4.3-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ImageMagick-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-0397", value:TRUE);
 set_kb_item(name:"CVE-2005-4601", value:TRUE);
 set_kb_item(name:"CVE-2006-0082", value:TRUE);
}
