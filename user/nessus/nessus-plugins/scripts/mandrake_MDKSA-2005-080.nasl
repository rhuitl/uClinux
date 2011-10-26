#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:080
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18173);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0605");
 
 name["english"] = "MDKSA-2005:080: xpm";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:080 (xpm).



The XPM library which is part of the XFree86/XOrg project is used by several
GUI applications to process XPM image files.

An integer overflow flaw was found in libXPM, which is used by some
applications for loading of XPM images. An attacker could create a malicious
XPM file that would execute arbitrary code via a negative bitmap_unit value if
opened by a victim using an application linked to the vulnerable library.

Updated packages are patched to correct all these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:080
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xpm package";
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
if ( rpm_check( reference:"libxpm4-3.4k-27.4.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxpm4-devel-3.4k-27.4.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxpm4-3.4k-28.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxpm4-devel-3.4k-28.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxpm4-3.4k-30.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxpm4-devel-3.4k-30.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"xpm-", release:"MDK10.0")
 || rpm_exists(rpm:"xpm-", release:"MDK10.1")
 || rpm_exists(rpm:"xpm-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-0605", value:TRUE);
}
