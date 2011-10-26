#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:165
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16082);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0888", "CVE-2004-1125");
 
 name["english"] = "MDKSA-2004:165: koffice";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:165 (koffice).



Chris Evans discovered numerous vulnerabilities in the xpdf package, which also
effect software using embedded xpdf code, such as koffice (CVE-2004-0888).

Multiple integer overflow issues affecting xpdf-2.0 and xpdf-3.0. Also programs
like koffice which have embedded versions of xpdf. These can result in writing
an arbitrary byte to an attacker controlled location which probably could lead
to arbitrary code execution.

iDefense also reported a buffer overflow vulnerability, which affects versions
of xpdf <= xpdf-3.0 and several programs, like koffice, which use embedded xpdf
code. An attacker could construct a malicious payload file which could enable
arbitrary code execution on the target system (CVE-2004-1125).

The updated packages are patched to protect against these vulnerabilities.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:165
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the koffice package";
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
if ( rpm_check( reference:"koffice-1.3-12.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-1.3-12.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-devel-1.3-12.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-1.3.3-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-karbon-1.3.3-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-kformula-1.3.3-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-kivio-1.3.3-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-koshell-1.3.3-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-kpresenter-1.3.3-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-kspread-1.3.3-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-kugar-1.3.3-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-kword-1.3.3-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-progs-1.3.3-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-karbon-1.3.3-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-kformula-1.3.3-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-kivio-1.3.3-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-koshell-1.3.3-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-kpresenter-1.3.3-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-kspread-1.3.3-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-kspread-devel-1.3.3-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-kugar-1.3.3-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-kugar-devel-1.3.3-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-kword-1.3.3-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-kword-devel-1.3.3-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-progs-1.3.3-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkoffice2-progs-devel-1.3.3-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"koffice-", release:"MDK10.0")
 || rpm_exists(rpm:"koffice-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2004-0888", value:TRUE);
 set_kb_item(name:"CVE-2004-1125", value:TRUE);
}
