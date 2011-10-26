#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:098
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14754);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0015");
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2004-0687", "CVE-2004-0688");
 script_bugtraq_id(11196);
 
 name["english"] = "MDKSA-2004:098: libxpm4";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:098 (libxpm4).


Chris Evans found several stack and integer overflows in the libXpm code of
X.Org/XFree86 (from which the libxpm code is derived):
Stack overflows (CVE-2004-0687):
Careless use of strcat() in both the XPMv1 and XPMv2/3 xpmParseColors code leads
to a stack based overflow (parse.c).
Stack overflow reading pixel values in ParseAndPutPixels (create.c) as well as
ParsePixels (parse.c).
Integer Overflows (CVE-2004-0688):
Integer overflow allocating colorTable in xpmParseColors (parse.c) - probably a
crashable but not exploitable offence.
The updated packages have patches from Chris Evans and Matthieu Herrb to address
these vulnerabilities.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:098
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libxpm4 package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"libxpm4-3.4k-27.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxpm4-devel-3.4k-27.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxpm4-3.4k-27.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxpm4-devel-3.4k-27.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"libxpm4-", release:"MDK10.0")
 || rpm_exists(rpm:"libxpm4-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0687", value:TRUE);
 set_kb_item(name:"CVE-2004-0688", value:TRUE);
}
