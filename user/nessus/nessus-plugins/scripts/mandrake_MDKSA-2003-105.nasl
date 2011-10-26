#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:105
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14087);
 script_bugtraq_id(9005);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0886");
 
 name["english"] = "MDKSA-2003:105: hylafax";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:105 (hylafax).


During a code review of the hfaxd server, part of the hylafax package, the SuSE
Security Team discovered a format bug condition that allows remote attackers to
execute arbitrary code as the root user. Updated packages have been patched to
correct the problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:105
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the hylafax package";
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
if ( rpm_check( reference:"hylafax-4.1.3-5.1.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-client-4.1.3-5.1.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-server-4.1.3-5.1.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.1.1-4.1.3-5.1.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.1.1-devel-4.1.3-5.1.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-4.1.5-1.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-client-4.1.5-1.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-server-4.1.5-1.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.1.1-4.1.5-1.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.1.1-devel-4.1.5-1.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-4.1.6-3.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-client-4.1.6-3.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-server-4.1.6-3.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.1.1-4.1.6-3.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.1.1-devel-4.1.6-3.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"hylafax-", release:"MDK9.0")
 || rpm_exists(rpm:"hylafax-", release:"MDK9.1")
 || rpm_exists(rpm:"hylafax-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0886", value:TRUE);
}
