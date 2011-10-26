#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:036
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14135);
 script_bugtraq_id(10168);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0409");
 
 name["english"] = "MDKSA-2004:036: xchat";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:036 (xchat).


A remotely exploitable vulnerability was discovered in the Socks-5 proxy code in
XChat. By default, socks5 traversal is disabled, and one would also need to
connect to an attacker's own custom proxy server in order for this to be
exploited. Successful exploitation could lead to arbitrary code execution as the
user running XChat.
The provided packages are patched to prevent this problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:036
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xchat package";
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
if ( rpm_check( reference:"xchat-2.0.7-6.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xchat-perl-2.0.7-6.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xchat-python-2.0.7-6.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xchat-tcl-2.0.7-6.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xchat-2.0.4-7.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xchat-perl-2.0.4-7.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xchat-python-2.0.4-7.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xchat-tcl-2.0.4-7.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"xchat-", release:"MDK10.0")
 || rpm_exists(rpm:"xchat-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0409", value:TRUE);
}
