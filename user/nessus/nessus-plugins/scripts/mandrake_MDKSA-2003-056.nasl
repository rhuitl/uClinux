#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:056
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14040);
 script_bugtraq_id(7382);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0211");
 
 name["english"] = "MDKSA-2003:056: xinetd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:056 (xinetd).


A vulnerability was discovered in xinetd where memory was allocated and never
freed if a connection was refused for any reason. Because of this bug, an
attacker could crash the xinetd server, making unavailable all of the services
it controls. Other flaws were also discovered that could cause incorrect
operation in certain strange configurations.
These issues have been fixed upstream in xinetd version 2.3.11 which are
provided in this update.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:056
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xinetd package";
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
if ( rpm_check( reference:"xinetd-2.3.11-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xinetd-ipv6-2.3.11-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xinetd-2.3.11-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xinetd-ipv6-2.3.11-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xinetd-2.3.11-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xinetd-ipv6-2.3.11-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"xinetd-", release:"MDK8.2")
 || rpm_exists(rpm:"xinetd-", release:"MDK9.0")
 || rpm_exists(rpm:"xinetd-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0211", value:TRUE);
}
