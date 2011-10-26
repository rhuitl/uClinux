#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:002
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16115);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0015");
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-1183", "CVE-2004-1308");
 
 name["english"] = "MDKSA-2005:002: wxGTK2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:002 (wxGTK2).



Several vulnerabilities have been discovered in the libtiff package; wxGTK2
uses a libtiff code tree, so it may have the same vulnerabilities:

iDefense reported the possibility of remote exploitation of an integer overflow
in libtiff that may allow for the execution of arbitrary code.

The overflow occurs in the parsing of TIFF files set with the STRIPOFFSETS
flag.

iDefense also reported a heap-based buffer overflow vulnerability within the
LibTIFF package could allow attackers to execute arbitrary code.
(CVE-2004-1308)

The vulnerability specifically exists due to insufficient validation of
user-supplied data when calculating the size of a directory entry.

The updated packages are patched to protect against these vulnerabilities.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:002
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the wxGTK2 package";
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
if ( rpm_check( reference:"libwxgtk2.5-2.5.0-0.cvs20030817.1.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwxgtk2.5-devel-2.5.0-0.cvs20030817.1.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwxgtkgl2.5-2.5.0-0.cvs20030817.1.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wxGTK2.5-2.5.0-0.cvs20030817.1.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwxgtk2.5_1-2.5.1-5.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwxgtk2.5_1-devel-2.5.1-5.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwxgtkgl2.5_1-2.5.1-5.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wxGTK2.5-2.5.1-5.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"wxGTK2-", release:"MDK10.0")
 || rpm_exists(rpm:"wxGTK2-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2004-1183", value:TRUE);
 set_kb_item(name:"CVE-2004-1308", value:TRUE);
}
