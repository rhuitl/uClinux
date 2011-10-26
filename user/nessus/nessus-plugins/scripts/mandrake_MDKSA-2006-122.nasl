#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:122
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22053);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2004-0941", "CVE-2004-0990", "CVE-2006-1017", "CVE-2006-1990", "CVE-2006-2563", "CVE-2006-2660", "CVE-2006-2906", "CVE-2006-3011", "CVE-2006-3016", "CVE-2006-3017", "CVE-2006-3018");
 
 name["english"] = "MDKSA-2006:122: php";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:122 (php).


Updated packages have been patched to address all these issues. Once
these packages have been installed, you will need to restart Apache
(service httpd restart) in order for the changes to take effect.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:122
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
if ( rpm_check( reference:"libphp_common432-4.3.10-7.14.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php432-devel-4.3.10-7.14.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cgi-4.3.10-7.14.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cli-4.3.10-7.14.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.3.10-6.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libphp5_common5-5.0.4-9.12.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cgi-5.0.4-9.12.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cli-5.0.4-9.12.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-curl-5.0.4-1.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-5.0.4-9.12.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-fcgi-5.0.4-9.12.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-imap-5.0.4-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"php-", release:"MDK10.2")
 || rpm_exists(rpm:"php-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2004-0941", value:TRUE);
 set_kb_item(name:"CVE-2004-0990", value:TRUE);
 set_kb_item(name:"CVE-2006-1017", value:TRUE);
 set_kb_item(name:"CVE-2006-1990", value:TRUE);
 set_kb_item(name:"CVE-2006-2563", value:TRUE);
 set_kb_item(name:"CVE-2006-2660", value:TRUE);
 set_kb_item(name:"CVE-2006-2906", value:TRUE);
 set_kb_item(name:"CVE-2006-3011", value:TRUE);
 set_kb_item(name:"CVE-2006-3016", value:TRUE);
 set_kb_item(name:"CVE-2006-3017", value:TRUE);
 set_kb_item(name:"CVE-2006-3018", value:TRUE);
}
