#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:001
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16114);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0015");
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-1183", "CVE-2004-1308");
 
 name["english"] = "MDKSA-2005:001: libtiff";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:001 (libtiff).



Several vulnerabilities have been discovered in the libtiff package:

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



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:001
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libtiff package";
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
if ( rpm_check( reference:"libtiff-progs-3.5.7-11.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-3.5.7-11.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-devel-3.5.7-11.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-static-devel-3.5.7-11.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-progs-3.6.1-4.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-3.6.1-4.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-devel-3.6.1-4.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-static-devel-3.6.1-4.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-progs-3.5.7-11.5.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-3.5.7-11.5.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-devel-3.5.7-11.5.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-static-devel-3.5.7-11.5.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"libtiff-", release:"MDK10.0")
 || rpm_exists(rpm:"libtiff-", release:"MDK10.1")
 || rpm_exists(rpm:"libtiff-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-1183", value:TRUE);
 set_kb_item(name:"CVE-2004-1308", value:TRUE);
}
