#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:029
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14013);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-a-0008");
 script_bugtraq_id(6963);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0033");
 
 name["english"] = "MDKSA-2003:029: snort";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:029 (snort).


A buffer overflow was discovered in the snort RPC normalization routines by
ISS-XForce which can cause snort to execute arbitrary code embedded within
sniffed network packets. The rpc_decode preprocessor is enabled by default. The
snort developers have released version 1.9.1 to correct this behaviour; snort
versions from 1.8 up to 1.9.0 are vulnerable.
For those unable to upgrade, you can disable the rpc_decode preprocessor by
commenting out the line (place a '#' character at the beginning of the line)
that enables it in your snort.conf file:
preprocessor rpc_decode


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:029
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the snort package";
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
if ( rpm_check( reference:"snort-1.9.1-0.5mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-bloat-1.9.1-0.5mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-mysql+flexresp-1.9.1-0.5mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-mysql-1.9.1-0.5mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-plain+flexresp-1.9.1-0.5mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-postgresql-1.9.1-0.5mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-snmp+flexresp-1.9.1-0.5mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-snmp-1.9.1-0.5mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-1.9.1-0.5mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-bloat-1.9.1-0.5mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-mysql+flexresp-1.9.1-0.5mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-mysql-1.9.1-0.5mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-plain+flexresp-1.9.1-0.5mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-postgresql-1.9.1-0.5mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-snmp+flexresp-1.9.1-0.5mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-snmp-1.9.1-0.5mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"snort-", release:"MDK8.2")
 || rpm_exists(rpm:"snort-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0033", value:TRUE);
}
