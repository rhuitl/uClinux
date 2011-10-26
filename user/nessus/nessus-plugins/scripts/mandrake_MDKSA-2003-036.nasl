#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:036
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14020);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0146");
 
 name["english"] = "MDKSA-2003:036: netpbm";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:036 (netpbm).


Several math overflow errors were found in NetPBM by Al Viro and Alan Cox. While
these programs are not installed suid root, they are often used to prepare data
for processing. These errors may permit remote attackers to cause a denial of
service or execute arbitrary code in any programs or scripts that use these
graphics conversion tools.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:036
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the netpbm package";
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
if ( rpm_check( reference:"libnetpbm9-9.20-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnetpbm9-devel-9.20-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netpbm-9.20-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnetpbm9-9.24-4.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnetpbm9-devel-9.24-4.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnetpbm9-static-devel-9.24-4.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netpbm-9.24-4.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnetpbm9-9.24-4.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnetpbm9-devel-9.24-4.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnetpbm9-static-devel-9.24-4.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netpbm-9.24-4.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"netpbm-", release:"MDK8.2")
 || rpm_exists(rpm:"netpbm-", release:"MDK9.0")
 || rpm_exists(rpm:"netpbm-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0146", value:TRUE);
}
