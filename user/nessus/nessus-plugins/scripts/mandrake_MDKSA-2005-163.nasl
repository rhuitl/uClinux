#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:163
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19918);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2558");
 
 name["english"] = "MDKSA-2005:163: MySQL";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:163 (MySQL).



A stack-based buffer overflow was discovered in the init_syms function in MySQL
that allows authenticated users that can create user-defined functions to
execute arbitrary code via a long function_name field.

The updated packages have been patched to address these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:163
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the MySQL package";
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
if ( rpm_check( reference:"libmysql12-4.0.20-3.5.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmysql12-devel-4.0.20-3.5.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-4.0.20-3.5.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-Max-4.0.20-3.5.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-bench-4.0.20-3.5.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-client-4.0.20-3.5.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-common-4.0.20-3.5.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmysql14-4.1.11-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmysql14-devel-4.1.11-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-4.1.11-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-Max-4.1.11-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-NDB-4.1.11-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-bench-4.1.11-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-client-4.1.11-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-common-4.1.11-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"MySQL-", release:"MDK10.1")
 || rpm_exists(rpm:"MySQL-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2558", value:TRUE);
}
