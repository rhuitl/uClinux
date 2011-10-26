#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:045
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20963);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-1636");
 
 name["english"] = "MDKSA-2006:045: MySQL";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:045 (MySQL).



Eric Romang discovered a temporary file vulnerability in the mysql_install_db
script provided with MySQL. This vulnerability only affects versions of MySQL
4.1.x prior to 4.1.12. The updated packages have been patched to address this
issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:045
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the MySQL package";
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
if ( rpm_check( reference:"libmysql14-4.1.11-1.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmysql14-devel-4.1.11-1.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-4.1.11-1.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-bench-4.1.11-1.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-client-4.1.11-1.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-common-4.1.11-1.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-Max-4.1.11-1.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-NDB-4.1.11-1.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"MySQL-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1636", value:TRUE);
}
