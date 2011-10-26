#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:131
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19891);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2360", "CVE-2005-2361", "CVE-2005-2362", "CVE-2005-2363", "CVE-2005-2364", "CVE-2005-2365", "CVE-2005-2366", "CVE-2005-2367");
 
 name["english"] = "MDKSA-2005:131: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:131 (ethereal).



A number of vulnerabilities were discovered in versions of Ethereal prior to
version 0.10.12, including:

The SMB dissector could overflow a buffer or exhaust memory (CVE-2005-2365).

iDefense discovered that several dissectors are vulnerable to format string
overflows (CVE-2005-2367).

A number of other portential crash issues in various dissectors have also been
corrected.

This update provides Ethereal 0.10.12 which is not vulnerable to these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:131
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal package";
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
if ( rpm_check( reference:"ethereal-0.10.12-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-tools-0.10.12-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libethereal0-0.10.12-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tethereal-0.10.12-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.12-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-tools-0.10.12-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libethereal0-0.10.12-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tethereal-0.10.12-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ethereal-", release:"MDK10.1")
 || rpm_exists(rpm:"ethereal-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2360", value:TRUE);
 set_kb_item(name:"CVE-2005-2361", value:TRUE);
 set_kb_item(name:"CVE-2005-2362", value:TRUE);
 set_kb_item(name:"CVE-2005-2363", value:TRUE);
 set_kb_item(name:"CVE-2005-2364", value:TRUE);
 set_kb_item(name:"CVE-2005-2365", value:TRUE);
 set_kb_item(name:"CVE-2005-2366", value:TRUE);
 set_kb_item(name:"CVE-2005-2367", value:TRUE);
}
