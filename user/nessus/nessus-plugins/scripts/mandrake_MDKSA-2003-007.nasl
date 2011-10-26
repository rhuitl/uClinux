#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:007
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13992);
 script_bugtraq_id(6627);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0026");
 
 name["english"] = "MDKSA-2003:007: dhcp";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:007 (dhcp).


Several potential vulnerabilities were detected by the ISC (Internet Software
Consortium) in their dhcp server software. The vulnerabilities affect the
minires library and may be exploitable as stack buffer overflows, which could
lead to remote code execution. All Mandrake Linux users are encouraged to
upgrade; only Mandrake Linux 8.0 came with dhcp 2.x and is not vulnerable.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:007
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the dhcp package";
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
if ( rpm_check( reference:"dhcp-3.0b2pl9-4.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-client-3.0b2pl9-4.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-relay-3.0b2pl9-4.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-client-3.0-0.rc12.2.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-common-3.0-0.rc12.2.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-devel-3.0-0.rc12.2.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-relay-3.0-0.rc12.2.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-server-3.0-0.rc12.2.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-client-3.0-1rc8.2.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-common-3.0-1rc8.2.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-devel-3.0-1rc8.2.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-relay-3.0-1rc8.2.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-server-3.0-1rc8.2.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-client-3.0-1rc9.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-common-3.0-1rc9.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-devel-3.0-1rc9.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-relay-3.0-1rc9.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcp-server-3.0-1rc9.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"dhcp-", release:"MDK7.2")
 || rpm_exists(rpm:"dhcp-", release:"MDK8.1")
 || rpm_exists(rpm:"dhcp-", release:"MDK8.2")
 || rpm_exists(rpm:"dhcp-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0026", value:TRUE);
}
