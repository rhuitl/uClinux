#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:143
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19900);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2452");
 
 name["english"] = "MDKSA-2005:143: kdegraphics";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:143 (kdegraphics).



Wouter Hanegraaff discovered that the TIFF library did not sufficiently
validate the 'YCbCr subsampling' value in TIFF image headers. Decoding a
malicious image with a zero value resulted in an arithmetic exception, which
can cause a program that uses the TIFF library to crash.

Kdegraphics < 3.3 uses an embedded libtiff source tree for kfax, and as such
has the same vulnerability.

The updated packages are patched to protect against this vulnerability.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:143
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdegraphics package";
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
if ( rpm_check( reference:"kdegraphics-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-common-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kdvi-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kfax-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kghostview-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kiconedit-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kooka-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kpaint-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kpdf-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kpovmodeler-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kruler-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-ksnapshot-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-ksvg-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kuickshow-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kview-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-mrmlsearch-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-common-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-common-devel-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-kghostview-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-kghostview-devel-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-kooka-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-kooka-devel-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-kpovmodeler-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-kpovmodeler-devel-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-ksvg-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-ksvg-devel-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-kuickshow-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-kview-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-kview-devel-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-mrmlsearch-3.2.3-17.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kdegraphics-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-2452", value:TRUE);
}
