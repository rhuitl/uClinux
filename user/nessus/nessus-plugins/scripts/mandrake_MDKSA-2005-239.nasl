#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:239
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20470);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-4604");
 
 name["english"] = "MDKSA-2005:239: printer-filters-utils";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:239 (printer-filters-utils).



'newbug' discovered a local root vulnerability in the mtink binary, which has a
buffer overflow in its handling of the HOME environment variable, allowing the
possibility for a local user to gain root privileges. Mandriva encourages all
users to upgrade immediately. The updated packages have been patched to correct
these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:239
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the printer-filters-utils package";
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
if ( rpm_check( reference:"cups-drivers-10.1-0.2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"foomatic-db-3.0.1-0.20040828.1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"foomatic-db-engine-3.0.1-0.20040828.1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"foomatic-filters-3.0.1-0.20040828.1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ghostscript-7.07-25.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ghostscript-module-X-7.07-25.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgimpprint1-4.2.7-8.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgimpprint1-devel-4.2.7-8.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libijs0-0.34-82.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libijs0-devel-0.34-82.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"printer-filters-10.1-0.2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"printer-testpages-10.1-0.2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"printer-utils-10.1-0.2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-drivers-10.2-0.11.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"printer-filters-10.2-0.11.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"printer-utils-10.2-0.11.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-drivers-2006-7.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"printer-filters-2006-7.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"printer-utils-2006-7.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"printer-filters-utils-", release:"MDK10.1")
 || rpm_exists(rpm:"printer-filters-utils-", release:"MDK10.2")
 || rpm_exists(rpm:"printer-filters-utils-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-4604", value:TRUE);
}
