#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:119
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15599);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0457", "CVE-2004-0835", "CVE-2004-0836", "CVE-2004-0837");
 
 name["english"] = "MDKSA-2004:119: MySQL";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:119 (MySQL).



A number of problems have been discovered in the MySQL database server:

Jeroen van Wolffelaar discovered an insecure temporary file vulnerability in
the mysqlhotcopy script when using the scp method (CVE-2004-0457).

Oleksandr Byelkin discovered that the 'ALTER TABLE ... RENAME' would check the
CREATE/INSERT rights of the old table rather than the new one (CVE-2004-0835).

Lukasz Wojtow discovered a buffer overrun in the mysql_real_connect function
(CVE-2004-0836).

Dean Ellis discovered that multiple threads ALTERing the same (or different)
MERGE tables to change the UNION can cause the server to crash or stall
(CVE-2004-0837).

The updated MySQL packages have been patched to protect against these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:119
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the MySQL package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"MySQL-4.0.18-1.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-Max-4.0.18-1.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-bench-4.0.18-1.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-client-4.0.18-1.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-common-4.0.18-1.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmysql12-4.0.18-1.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmysql12-devel-4.0.18-1.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-4.0.20-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-Max-4.0.20-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-bench-4.0.20-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-client-4.0.20-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-common-4.0.20-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmysql12-4.0.20-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmysql12-devel-4.0.20-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-4.0.15-1.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-Max-4.0.15-1.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-bench-4.0.15-1.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-client-4.0.15-1.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-common-4.0.15-1.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmysql12-4.0.15-1.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmysql12-devel-4.0.15-1.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"MySQL-", release:"MDK10.0")
 || rpm_exists(rpm:"MySQL-", release:"MDK10.1")
 || rpm_exists(rpm:"MySQL-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0457", value:TRUE);
 set_kb_item(name:"CVE-2004-0835", value:TRUE);
 set_kb_item(name:"CVE-2004-0836", value:TRUE);
 set_kb_item(name:"CVE-2004-0837", value:TRUE);
}
