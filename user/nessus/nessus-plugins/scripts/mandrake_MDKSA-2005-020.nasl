#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:020
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16257);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0064");
 
 name["english"] = "MDKSA-2005:020: kdegraphics";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:020 (kdegraphics).



A buffer overflow vulnerability was discovered in the xpdf PDF code, which
could allow for arbitrary code execution as the user viewing a PDF file. The
vulnerability exists due to insufficient bounds checking while processing a PDF
file that provides malicious values in the /Encrypt /Length tag. Kdegraphics
uses xpdf code and is susceptible to the same vulnerability.

10.1 packages also include a fix for ksvg kde bug #74457.

The updated packages have been patched to prevent these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:020
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
if ( rpm_check( reference:"kdegraphics-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-common-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kdvi-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kfax-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kghostview-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kiconedit-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kooka-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kpaint-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kpdf-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kpovmodeler-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kruler-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-ksnapshot-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-ksvg-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kuickshow-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kview-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-mrmlsearch-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-common-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-common-devel-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-kooka-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-kooka-devel-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-kpovmodeler-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-kpovmodeler-devel-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-ksvg-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-ksvg-devel-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-kuickshow-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-kview-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-kview-devel-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-mrmlsearch-3.2-15.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-common-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kdvi-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kfax-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kghostview-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kiconedit-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kooka-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kpaint-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kpdf-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kpovmodeler-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kruler-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-ksnapshot-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-ksvg-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kuickshow-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-kview-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-mrmlsearch-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-common-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-common-devel-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-kghostview-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-kghostview-devel-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-kooka-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-kooka-devel-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-kpovmodeler-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-kpovmodeler-devel-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-ksvg-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-ksvg-devel-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-kuickshow-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-kview-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-kview-devel-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdegraphics0-mrmlsearch-3.2.3-17.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kdegraphics-", release:"MDK10.0")
 || rpm_exists(rpm:"kdegraphics-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-0064", value:TRUE);
}
