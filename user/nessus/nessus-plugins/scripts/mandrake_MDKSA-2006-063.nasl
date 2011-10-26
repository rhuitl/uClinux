#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:063
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21178);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-1490");
 
 name["english"] = "MDKSA-2006:063: php";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:063 (php).



A vulnerability was discovered where the html_entity_decode() function would
return a chunk of memory with length equal to the string supplied, which could
include php code, php ini data, other user data, etc. Note that by default,
Corporate 3.0 and Mandriva Linux LE2005 ship with magic_quotes_gpc on which
seems to protect against this vulnerability 'out of the box' but users are
encourages to upgrade regardless. Once the upgraded packages have been
installed, users will need to issue a 'service httpd restart' in order for the
fixed packages to be properly loaded. Updated packages have been patched to
correct this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:063
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
if ( rpm_check( reference:"libphp_common432-4.3.10-7.8.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php432-devel-4.3.10-7.8.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cgi-4.3.10-7.8.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cli-4.3.10-7.8.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libphp5_common5-5.0.4-9.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cgi-5.0.4-9.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cli-5.0.4-9.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-5.0.4-9.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-fcgi-5.0.4-9.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"php-", release:"MDK10.2")
 || rpm_exists(rpm:"php-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-1490", value:TRUE);
}
