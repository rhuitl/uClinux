#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:005
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14105);
 script_bugtraq_id(9376);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0013");
 
 name["english"] = "MDKSA-2004:005: jabber";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:005 (jabber).


A vulnerability was found in the jabber program where a bug in the handling of
SSL connections could cause the server process to crash, resulting in a DoS
(Denial of Service).
The updated packages are patched to correct the problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:005
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the jabber package";
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
if ( rpm_check( reference:"jabber-1.4.2a-10.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"jabber-1.4.2a-10.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"jabber-aim-1.4.2a-10.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"jabber-conference-1.4.2a-10.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"jabber-icq-1.4.2a-10.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"jabber-jud-1.4.2a-10.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"jabber-msn-1.4.2a-10.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"jabber-yahoo-1.4.2a-10.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"jabber-", release:"MDK9.1")
 || rpm_exists(rpm:"jabber-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0013", value:TRUE);
}
