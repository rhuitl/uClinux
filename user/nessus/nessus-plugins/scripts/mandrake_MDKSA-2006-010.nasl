#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:010
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20476);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3193", "CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627", "CVE-2005-3628");
 
 name["english"] = "MDKSA-2006:010: cups";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:010 (cups).



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
'DCTDecode' stream. (CVE-2005-3627) CUPS uses an embedded copy of the xpdf
code, with the same vulnerabilities. The updated packages have been patched to
correct these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:010
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cups package";
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
if ( rpm_check( reference:"cups-1.1.21-0.rc1.7.8.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-common-1.1.21-0.rc1.7.8.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-serial-1.1.21-0.rc1.7.8.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups2-1.1.21-0.rc1.7.8.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups2-devel-1.1.21-0.rc1.7.8.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.23-11.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-common-1.1.23-11.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-serial-1.1.23-11.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups2-1.1.23-11.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups2-devel-1.1.23-11.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.23-17.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-common-1.1.23-17.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-serial-1.1.23-17.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups2-1.1.23-17.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups2-devel-1.1.23-17.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cups-", release:"MDK10.1")
 || rpm_exists(rpm:"cups-", release:"MDK10.2")
 || rpm_exists(rpm:"cups-", release:"MDK2006.0") )
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
