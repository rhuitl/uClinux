#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:068
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14167);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0594", "CVE-2004-0595");
 
 name["english"] = "MDKSA-2004:068: php";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:068 (php).


Stefan Esser discovered a remotely exploitable vulnerability in PHP where a
remote attacker could trigger a memory_limit request termination in places where
an interruption is unsafe. This could be used to execute arbitrary code.
As well, Stefan Esser also found a vulnerability in the handling of allowed tags
within PHP's strip_tags() function. This could lead to a number of XSS issues on
sites that rely on strip_tags(); however, this only seems to affect the Internet
Explorer and Safari browsers.
The updated packages have been patched to correct the problem and all users are
encouraged to upgrade immediately.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:068
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the php package";
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
if ( rpm_check( reference:"libphp_common432-4.3.4-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cgi-4.3.4-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cli-4.3.4-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php432-devel-4.3.4-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libphp_common430-430-11.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cgi-4.3.1-11.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cli-4.3.1-11.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php430-devel-430-11.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libphp_common432-4.3.3-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cgi-4.3.3-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cli-4.3.3-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php432-devel-4.3.3-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"php-", release:"MDK10.0")
 || rpm_exists(rpm:"php-", release:"MDK9.1")
 || rpm_exists(rpm:"php-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0594", value:TRUE);
 set_kb_item(name:"CVE-2004-0595", value:TRUE);
}
