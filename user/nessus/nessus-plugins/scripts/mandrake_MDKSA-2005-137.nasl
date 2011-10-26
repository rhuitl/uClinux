#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:137
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19894);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2177");
 
 name["english"] = "MDKSA-2005:137: ucd-snmp";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:137 (ucd-snmp).



A Denial of Service vulnerability was discovered in the way that ucd-snmp uses
network stream protocols. A remote attacker could send a ucd-snmp agent a
specially crafted packet that would cause the agent to crash.

The updated packages have been patched to correct this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:137
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ucd-snmp package";
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
if ( rpm_check( reference:"libsnmp0-4.2.3-8.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsnmp0-devel-4.2.3-8.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ucd-snmp-4.2.3-8.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ucd-snmp-utils-4.2.3-8.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsnmp0-4.2.3-11.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsnmp0-devel-4.2.3-11.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ucd-snmp-4.2.3-11.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ucd-snmp-utils-4.2.3-11.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ucd-snmp-", release:"MDK10.0")
 || rpm_exists(rpm:"ucd-snmp-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-2177", value:TRUE);
}
