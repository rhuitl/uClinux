#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:028
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20849);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0207", "CVE-2006-0208");
 
 name["english"] = "MDKSA-2006:028: php";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:028 (php).



Multiple response splitting vulnerabilities in PHP allow remote attackers to
inject arbitrary HTTP headers via unknown attack vectors, possibly involving a
crafted Set-Cookie header, related to the (1) session extension (aka ext/
session) and the (2) header function. (CVE-2006-0207) Multiple cross-site
scripting (XSS) vulnerabilities in PHP allow remote attackers to inject
arbitrary web script or HTML via unknown attack vectors in 'certain error
conditions.' (CVE-2006-0208). This issue does not affect Corporate Server 2.1.
Updated packages are patched to address these issues. Users must execute
'service httpd restart' for the new PHP modules to be loaded by Apache.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:028
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the php package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"libphp_common432-4.3.8-3.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php432-devel-4.3.8-3.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cgi-4.3.8-3.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cli-4.3.8-3.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libphp_common432-4.3.10-7.5.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php432-devel-4.3.10-7.5.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cgi-4.3.10-7.5.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cli-4.3.10-7.5.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libphp5_common5-5.0.4-9.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cgi-5.0.4-9.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cli-5.0.4-9.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-5.0.4-9.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-fcgi-5.0.4-9.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"php-", release:"MDK10.1")
 || rpm_exists(rpm:"php-", release:"MDK10.2")
 || rpm_exists(rpm:"php-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-0207", value:TRUE);
 set_kb_item(name:"CVE-2006-0208", value:TRUE);
}
