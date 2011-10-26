#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:070
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18032);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0957");
 
 name["english"] = "MDKSA-2005:070: MySQL";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:070 (MySQL).



A vulnerability in MySQL would allow a user with grant privileges to a database
with a name containing an underscore character ('_') to have the ability to
grant privileges to other databases with similar names. This problem was
previously discovered and fixed, but a new case where the problem still existed
was recently discovered.

The updated packages have been patched to correct this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:070
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
if ( rpm_check( reference:"libmysql12-4.0.18-1.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmysql12-devel-4.0.18-1.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-4.0.18-1.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-Max-4.0.18-1.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-bench-4.0.18-1.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-client-4.0.18-1.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-common-4.0.18-1.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmysql12-4.0.20-3.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmysql12-devel-4.0.20-3.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-4.0.20-3.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-Max-4.0.20-3.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-bench-4.0.20-3.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-client-4.0.20-3.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-common-4.0.20-3.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"MySQL-", release:"MDK10.0")
 || rpm_exists(rpm:"MySQL-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2004-0957", value:TRUE);
}
