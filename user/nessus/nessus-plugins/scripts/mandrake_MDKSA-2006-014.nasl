#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:014
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20793);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0106");
 
 name["english"] = "MDKSA-2006:014: wine";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:014 (wine).



A vulnerability was discovered by H D Moore in Wine which implements the
SETABORTPROC GDI Escape function for Windows Metafile (WMF) files. This could
be abused by an attacker who is able to entice a user to open a specially
crafted WMF file from within a Wine-execute Windows application, possibly
resulting in the execution of arbitrary code with the privileges of the user
runing Wine. The updated packages have been patched to correct these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:014
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the wine package";
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
if ( rpm_check( reference:"libwine1-20050725-6.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwine1-capi-20050725-6.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwine1-devel-20050725-6.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwine1-twain-20050725-6.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wine-20050725-6.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"wine-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-0106", value:TRUE);
}
