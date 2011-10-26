#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:011
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20477);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3193", "CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627", "CVE-2005-3628");
 
 name["english"] = "MDKSA-2006:011: tetex";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:011 (tetex).



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
other vulnerbilities in the xpdf code base: Out-of-bounds heap accesses with
large or negative parameters to 'FlateDecode' stream. (CVE-2005-3192)
Out-of-bounds heap accesses with large or negative parameters to
'CCITTFaxDecode' stream. (CVE-2005-3624) Infinite CPU spins in various places
when stream ends unexpectedly. (CVE-2005-3625) NULL pointer crash in the
'FlateDecode' stream. (CVE-2005-3626) Overflows of compInfo array in
'DCTDecode' stream. (CVE-2005-3627) Possible to use index past end of array in
'DCTDecode' stream. (CVE-2005-3627) Possible out-of-bounds indexing trouble in
'DCTDecode' stream. (CVE-2005-3627) Tetex uses an embedded copy of the xpdf
code, with the same vulnerabilities. The updated packages have been patched to
correct these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:011
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the tetex package";
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
if ( rpm_check( reference:"jadetex-3.12-98.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-2.0.2-19.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-afm-2.0.2-19.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-context-2.0.2-19.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-devel-2.0.2-19.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-doc-2.0.2-19.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvilj-2.0.2-19.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvipdfm-2.0.2-19.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvips-2.0.2-19.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-latex-2.0.2-19.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-mfwin-2.0.2-19.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-texi2html-2.0.2-19.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-xdvi-2.0.2-19.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xmltex-1.9-46.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"jadetex-3.12-106.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-3.0-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-afm-3.0-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-context-3.0-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-devel-3.0-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-doc-3.0-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvilj-3.0-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvipdfm-3.0-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvips-3.0-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-latex-3.0-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-mfwin-3.0-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-texi2html-3.0-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-xdvi-3.0-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xmltex-1.9-54.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"jadetex-3.12-110.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-3.0-12.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-afm-3.0-12.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-context-3.0-12.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-devel-3.0-12.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-doc-3.0-12.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvilj-3.0-12.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvipdfm-3.0-12.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvips-3.0-12.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-latex-3.0-12.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-mfwin-3.0-12.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-texi2html-3.0-12.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-xdvi-3.0-12.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xmltex-1.9-58.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"tetex-", release:"MDK10.1")
 || rpm_exists(rpm:"tetex-", release:"MDK10.2")
 || rpm_exists(rpm:"tetex-", release:"MDK2006.0") )
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
