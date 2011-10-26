#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:045
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14029);
 script_bugtraq_id(7119);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0128", "CVE-2003-0129", "CVE-2003-0130");
 
 name["english"] = "MDKSA-2003:045: evolution";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:045 (evolution).


Several vulnerabilities were discovered in the Evolution email client. These
problems make it possible for a carefully constructed email message to crash the
program, causing general system instability by starving resources.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:045
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the evolution package";
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
if ( rpm_check( reference:"evolution-1.0.8-3.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"evolution-pilot-1.0.8-3.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libevolution0-1.0.8-3.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libevolution0-devel-1.0.8-3.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"evolution-1.2.4-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"evolution-pilot-1.2.4-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libevolution0-1.2.4-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libevolution0-devel-1.2.4-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"evolution-", release:"MDK9.0")
 || rpm_exists(rpm:"evolution-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0128", value:TRUE);
 set_kb_item(name:"CVE-2003-0129", value:TRUE);
 set_kb_item(name:"CVE-2003-0130", value:TRUE);
}
