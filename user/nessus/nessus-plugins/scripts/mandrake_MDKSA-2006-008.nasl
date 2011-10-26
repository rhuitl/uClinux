#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:008
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20474);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3193", "CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627", "CVE-2005-3628");
 
 name["english"] = "MDKSA-2006:008: koffice";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:008 (koffice).



Multiple heap-based buffer overflows in the DCTStream::readProgressiveSOF and
DCTStream::readBaselineSOF functions in the DCT stream parsing code (Stream.cc)
in xpdf 3.01 and earlier, allow user-complicit attackers to cause a denial of
service (heap corruption) and possibly execute arbitrary code via a crafted PDF
file with an out-of-range number of components (numComps), which is used as an
array index. (CVE-2005-3191) Heap-based buffer overflow in the StreamPredictor
function in Xpdf 3.01 allows remote attackers to execute arbitrary code via a
PDF file with an out-of-range numComps (number of components) field.
(CVE-2005-3192) Heap-based buffer overflow in the JPXStream::readCodestream
function in the JPX stream parsing code (JPXStream.c) for xpdf 3.01 and earlier
allows user-complicit attackers to cause a denial of service (heap corruption)
and possibly execute arbitrary code via a crafted PDF file with large size
values that cause insufficient memory to be allocated. (CVE-2005-3193) An
additional patch re-addresses memory allocation routines in goo/gmem.c (Martin
Pitt/Canonical, Dirk Mueller/KDE). In addition, Chris Evans discovered several
other vulnerabilities in the xpdf code base: Out-of-bounds heap accesses with
large or negative parameters to 'FlateDecode' stream. (CVE-2005-3192)
Out-of-bounds heap accesses with large or negative parameters to
'CCITTFaxDecode' stream. (CVE-2005-3624) Infinite CPU spins in various places
when stream ends unexpectedly. (CVE-2005-3625) NULL pointer crash in the
'FlateDecode' stream. (CVE-2005-3626) Overflows of compInfo array in
'DCTDecode' stream. (CVE-2005-3627) Possible to use index past end of array in
'DCTDecode' stream. (CVE-2005-3627) Possible out-of-bounds indexing trouble in
'DCTDecode' stream. (CVE-2005-3627) Koffice uses an embedded copy of the xpdf
code, with the same vulnerabilities. The updated packages have been patched to
correct these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:008
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the koffice package";
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
if ( rpm_check( reference:"koffice-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-karbon-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-kexi-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-kformula-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-kivio-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-koshell-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-kpresenter-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-krita-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-kspread-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-kugar-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-kword-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-progs-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-karbon-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-karbon-devel-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-kexi-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-kexi-devel-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-kformula-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-kformula-devel-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-kivio-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-kivio-devel-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-koshell-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-kpresenter-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-krita-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-krita-devel-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-kspread-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-kspread-devel-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-kugar-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-kugar-devel-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-kword-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-kword-devel-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-progs-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-progs-devel-1.4.2-11.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"koffice-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3191", value:TRUE);
 set_kb_item(name:"CVE-2005-3192", value:TRUE);
 set_kb_item(name:"CVE-2005-3193", value:TRUE);
 set_kb_item(name:"CVE-2005-3624", value:TRUE);
 set_kb_item(name:"CVE-2005-3625", value:TRUE);
 set_kb_item(name:"CVE-2005-3626", value:TRUE);
 set_kb_item(name:"CVE-2005-3627", value:TRUE);
 set_kb_item(name:"CVE-2005-3628", value:TRUE);
}
