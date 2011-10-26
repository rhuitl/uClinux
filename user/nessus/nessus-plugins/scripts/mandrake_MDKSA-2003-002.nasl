#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:002
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13987);
 script_bugtraq_id(6475);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-1384");
 
 name["english"] = "MDKSA-2003:002: xpdf";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:002 (xpdf).


The pdftops filter found in both the xpdf and CUPS packages suffers from an
integer overflow that can be exploited to gain the privilege of the victim user.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:002
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xpdf package";
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
if ( rpm_check( reference:"xpdf-1.01-4.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xpdf-1.01-4.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xpdf-1.01-4.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xpdf-1.01-4.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xpdf-1.01-4.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"xpdf-", release:"MDK7.2")
 || rpm_exists(rpm:"xpdf-", release:"MDK8.0")
 || rpm_exists(rpm:"xpdf-", release:"MDK8.1")
 || rpm_exists(rpm:"xpdf-", release:"MDK8.2")
 || rpm_exists(rpm:"xpdf-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-1384", value:TRUE);
}
