#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:034
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14133);
 script_bugtraq_id(10142);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0381", "CVE-2004-0388");
 
 name["english"] = "MDKSA-2004:034: MySQL";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:034 (MySQL).


Shaun Colley discovered that two scripts distributed with MySQL, the
'mysqld_multi' and 'mysqlbug' scripts, did not create temporary files in a
secure fashion. An attacker could create symbolic links in /tmp that could allow
for overwriting of files with the privileges of the user running the scripts.
The scripts have been patched in the updated packages to prevent this behaviour.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:034
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
if ( rpm_check( reference:"libmysql12-4.0.18-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmysql12-devel-4.0.18-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-4.0.18-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-Max-4.0.18-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-bench-4.0.18-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-client-4.0.18-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-common-4.0.18-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmysql12-4.0.11a-5.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmysql12-devel-4.0.11a-5.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-4.0.11a-5.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-Max-4.0.11a-5.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-bench-4.0.11a-5.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-client-4.0.11a-5.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-common-4.0.11a-5.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmysql12-4.0.15-1.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmysql12-devel-4.0.15-1.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-4.0.15-1.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-Max-4.0.15-1.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-bench-4.0.15-1.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-client-4.0.15-1.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-common-4.0.15-1.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"MySQL-", release:"MDK10.0")
 || rpm_exists(rpm:"MySQL-", release:"MDK9.1")
 || rpm_exists(rpm:"MySQL-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0381", value:TRUE);
 set_kb_item(name:"CVE-2004-0388", value:TRUE);
}
