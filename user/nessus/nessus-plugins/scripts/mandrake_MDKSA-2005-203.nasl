#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:203
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20438);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2958");
 
 name["english"] = "MDKSA-2005:203: gda2.0";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:203 (gda2.0).



Steve Kemp discovered two format string vulnerabilities in libgda2, the GNOME
Data Access library for GNOME2, which may lead to the execution of arbitrary
code in programs that use this library. The updated packages have been patched
to correct this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:203
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gda2.0 package";
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
if ( rpm_check( reference:"gda2.0-1.2.1-1.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gda2.0-bdb-1.2.1-1.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gda2.0-ldap-1.2.1-1.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gda2.0-mysql-1.2.1-1.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gda2.0-odbc-1.2.1-1.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gda2.0-postgres-1.2.1-1.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gda2.0-sqlite-1.2.1-1.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gda2.0-xbase-1.2.1-1.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgda2.0_3-1.2.1-1.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgda2.0_3-devel-1.2.1-1.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gda2.0-1.2.2-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gda2.0-bdb-1.2.2-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gda2.0-ldap-1.2.2-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gda2.0-mysql-1.2.2-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gda2.0-odbc-1.2.2-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gda2.0-postgres-1.2.2-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gda2.0-sqlite-1.2.2-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gda2.0-xbase-1.2.2-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgda2.0_3-1.2.2-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgda2.0_3-devel-1.2.2-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gda2.0-", release:"MDK10.2")
 || rpm_exists(rpm:"gda2.0-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-2958", value:TRUE);
}
