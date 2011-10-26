#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:034
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14018);
 script_bugtraq_id(6953);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0022", "CVE-2003-0023", "CVE-2003-0066");
 
 name["english"] = "MDKSA-2003:034: rxvt";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:034 (rxvt).


Digital Defense Inc. released a paper detailing insecurities in various terminal
emulators, including rxvt. Many of the features supported by these programs can
be abused when untrusted data is displayed on the screen. This abuse can be
anything from garbage data being displayed to the screen or a system compromise.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:034
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the rxvt package";
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
if ( rpm_check( reference:"rxvt-2.7.8-6.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rxvt-CJK-2.7.8-6.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rxvt-devel-2.7.8-6.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rxvt-2.7.8-6.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rxvt-CJK-2.7.8-6.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rxvt-devel-2.7.8-6.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rxvt-2.7.8-6.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rxvt-CJK-2.7.8-6.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rxvt-devel-2.7.8-6.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"rxvt-", release:"MDK8.2")
 || rpm_exists(rpm:"rxvt-", release:"MDK9.0")
 || rpm_exists(rpm:"rxvt-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0022", value:TRUE);
 set_kb_item(name:"CVE-2003-0023", value:TRUE);
 set_kb_item(name:"CVE-2003-0066", value:TRUE);
}
