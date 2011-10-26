#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:057
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14041);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0150");
 
 name["english"] = "MDKSA-2003:057: MySQL";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:057 (MySQL).


In MySQL 3.23.55 and earlier, MySQL would create world-writeable files and allow
mysql users to gain root privileges by using the 'SELECT * INTO OUTFILE'
operator to overwrite a configuration file, which could cause mysql to run as
root upon restarting the daemon.
This has been fixed upstream in version 3.23.56, which is provided for Mandrake
Linux 9.0 and Corporate Server 2.1 users. The other updated packages have been
patched to correct this issue.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:057
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
if ( rpm_check( reference:"libmysql10-3.23.47-5.4mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmysql10-devel-3.23.47-5.4mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-3.23.47-5.4mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-bench-3.23.47-5.4mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-client-3.23.47-5.4mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmysql10-3.23.56-1.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmysql10-devel-3.23.56-1.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-3.23.56-1.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-Max-3.23.56-1.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-bench-3.23.56-1.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MySQL-client-3.23.56-1.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"MySQL-", release:"MDK8.2")
 || rpm_exists(rpm:"MySQL-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0150", value:TRUE);
}
