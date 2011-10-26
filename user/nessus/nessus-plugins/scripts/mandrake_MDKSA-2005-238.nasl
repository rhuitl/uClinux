#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:238
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20469);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3883");
 
 name["english"] = "MDKSA-2005:238: php";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:238 (php).



A CRLF injection vulnerability in the mb_send_mail function in PHP before 5.1.0
might allow remote attackers to inject arbitrary e-mail headers via line feeds
(LF) in the 'To' address argument, when using sendmail as the MTA (mail
transfer agent). The updated packages have been patched to address this issue.
Once the new packages have been installed, you will need to restart your Apache
server using 'service httpd restart' in order for the new packages to take
effect.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:238
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
if ( rpm_check( reference:"libphp5_common5-5.0.4-9.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cgi-5.0.4-9.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cli-5.0.4-9.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-5.0.4-9.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-fcgi-5.0.4-9.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-mbstring-5.0.4-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"php-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3883", value:TRUE);
}
