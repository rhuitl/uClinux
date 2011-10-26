#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:115
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14097);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0935");
 
 name["english"] = "MDKSA-2003:115: net-snmp";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:115 (net-snmp).


A vulnerability in Net-SNMP versions prior to 5.0.9 could allow an existing
user/community to gain access to data in MIB objects that were explicitly
excluded from their view.
The updated packages provide Net-SNMP version 5.0.9 which is not vulnerable to
this issue and also fixes a number of other smaller bugs.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:115
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the net-snmp package";
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
if ( rpm_check( reference:"libnet-snmp50-5.0.9-1.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnet-snmp50-devel-5.0.9-1.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-5.0.9-1.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-mibs-5.0.9-1.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-trapd-5.0.9-1.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-utils-5.0.9-1.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnet-snmp50-5.0.9-7.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnet-snmp50-devel-5.0.9-7.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-5.0.9-7.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-mibs-5.0.9-7.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-trapd-5.0.9-7.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-utils-5.0.9-7.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"net-snmp-", release:"MDK9.1")
 || rpm_exists(rpm:"net-snmp-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0935", value:TRUE);
}
