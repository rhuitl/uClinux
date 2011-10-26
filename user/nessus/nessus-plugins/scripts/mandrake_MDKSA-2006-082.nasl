#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:082
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21357);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-2024", "CVE-2006-2025", "CVE-2006-2026", "CVE-2006-2120");
 
 name["english"] = "MDKSA-2006:082: libtiff";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:082 (libtiff).



Several bugs were discovered in libtiff that can lead to remote Denial

of Service attacks. These bugs can only be triggered by a user using

an application that uses libtiff to process malformed TIFF images.



The updated packages have been patched to correct these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:082
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libtiff package";
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
if ( rpm_check( reference:"libtiff3-3.6.1-11.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-devel-3.6.1-11.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-static-devel-3.6.1-11.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-progs-3.6.1-11.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-3.6.1-12.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-devel-3.6.1-12.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-static-devel-3.6.1-12.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-progs-3.6.1-12.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"libtiff-", release:"MDK10.2")
 || rpm_exists(rpm:"libtiff-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-2024", value:TRUE);
 set_kb_item(name:"CVE-2006-2025", value:TRUE);
 set_kb_item(name:"CVE-2006-2026", value:TRUE);
 set_kb_item(name:"CVE-2006-2120", value:TRUE);
}
