#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:014
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13922);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2002:014: ucd-snmp";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:014 (ucd-snmp).


The Oulu University Secure Programming Group (OUSPG) has identified numerous
vulnerabilities in multiple vendor SNMPv1 implementations. These vulnerabilities
may allow unauthorized privileged access, denial of service attacks, or unstable
behaviour.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:014
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ucd-snmp package";
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
if ( rpm_check( reference:"ucd-snmp-4.2.3-1.3mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ucd-snmp-devel-4.2.3-1.3mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ucd-snmp-utils-4.2.3-1.3mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ucd-snmp-4.2.3-1.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ucd-snmp-devel-4.2.3-1.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ucd-snmp-utils-4.2.3-1.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ucd-snmp-4.2.3-1.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ucd-snmp-devel-4.2.3-1.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ucd-snmp-utils-4.2.3-1.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsnmp0-4.2.3-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsnmp0-devel-4.2.3-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ucd-snmp-4.2.3-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ucd-snmp-utils-4.2.3-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
