#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:060
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17601);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0709", "CVE-2005-0710", "CVE-2005-0711");
 
 name["english"] = "MDKSA-2005:060: MySQL";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:060 (MySQL).



A number of vulnerabilities were discovered by Stefano Di Paola in the MySQL
server:

If an authenticated user had INSERT privileges on the 'mysql' database, the
CREATE FUNCTION command allowed that user to use libc functions to execute
arbitrary code with the privileges of the user running the database server
(mysql) (CVE-2005-0709).

If an authenticated user had INSERT privileges on the 'mysql' database, it was
possible to load a library located in an arbitrary directory by using INSERT
INTO mysql.func instead of CREATE FUNCTION. This also would allow the user to
execute arbitrary code with the privileges of the user running the database
server (CVE-2005-0710).

Finally, temporary files belonging to tables created with CREATE TEMPORARY
TABLE were handled in an insecure manner, allowing any local user to overwrite
arbitrary files with the privileges of the database server (CVE-2005-0711).

The updated packages have been patched to correct these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:060
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
if ( rpm_check( reference:"libmysql12-4.0.18-1.4.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmysql12-devel-4.0.18-1.4.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-4.0.18-1.4.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-Max-4.0.18-1.4.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-bench-4.0.18-1.4.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-client-4.0.18-1.4.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-common-4.0.18-1.4.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmysql12-4.0.20-3.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmysql12-devel-4.0.20-3.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-4.0.20-3.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-Max-4.0.20-3.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-bench-4.0.20-3.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-client-4.0.20-3.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-common-4.0.20-3.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"MySQL-", release:"MDK10.0")
 || rpm_exists(rpm:"MySQL-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-0709", value:TRUE);
 set_kb_item(name:"CVE-2005-0710", value:TRUE);
 set_kb_item(name:"CVE-2005-0711", value:TRUE);
}
