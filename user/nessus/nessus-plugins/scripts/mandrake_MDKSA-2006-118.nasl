#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:118
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22014);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-2198", "CVE-2006-2199", "CVE-2006-3117");
 
 name["english"] = "MDKSA-2006:118: OpenOffice.org";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:118 (OpenOffice.org).



OpenOffice.org 1.1.x up to 1.1.5 and 2.0.x before 2.0.3 allows user-complicit

attackers to conduct unauthorized activities via an OpenOffice document with

a malicious BASIC macro, which is executed without prompting the user.

(CVE-2006-2198)



An unspecified vulnerability in Java Applets in OpenOffice.org 1.1.x up to

1.1.5 and 2.0.x before 2.0.3 allows user-complicit attackers to escape the

Java sandbox and conduct unauthorized activities via certain applets in

OpenOffice documents. (CVE-2006-2199)



Heap-based buffer overflow in OpenOffice.org 1.1.x up to 1.1.5 and 2.0.x

before 2.0.3 allows user-complicit attackers to execute arbitrary code via a

crafted OpenOffice XML document that is not properly handled by (1) Calc,

(2) Draw, (3) Impress, (4) Math, or (5) Writer, aka 'File Format / Buffer

Overflow Vulnerability.' (CVE-2006-3117)



Updated packages are patched to address this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:118
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the OpenOffice.org package";
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
if ( rpm_check( reference:"OpenOffice.org-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-help-cs-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-help-de-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-help-en-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-help-es-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-help-eu-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-help-fi-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-help-fr-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-help-it-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-help-ja-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-help-ko-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-help-nl-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-help-pt_BR-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-help-ru-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-help-sk-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-help-sl-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-help-sv-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-help-tr-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-help-zh_CN-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-help-zh_TW-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-af-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-ar-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-ca-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-cs-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-cy-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-da-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-de-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-el-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-en-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-es-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-et-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-eu-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-fi-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-fr-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-he-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-hu-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-it-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-ja-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-ko-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-nb-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-nl-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-nn-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-ns-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-pl-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-pt-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-pt_BR-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-ru-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-sk-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-sl-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-sv-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-tr-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-zh_CN-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-zh_TW-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-l10n-zu-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-libs-1.1.5-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"OpenOffice.org-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-2198", value:TRUE);
 set_kb_item(name:"CVE-2006-2199", value:TRUE);
 set_kb_item(name:"CVE-2006-3117", value:TRUE);
}
