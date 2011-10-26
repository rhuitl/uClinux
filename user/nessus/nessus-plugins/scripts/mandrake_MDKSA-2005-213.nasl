#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:213
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20445);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3054", "CVE-2005-3319", "CVE-2005-3353", "CVE-2005-3388", "CVE-2005-3389", "CVE-2005-3390");
 
 name["english"] = "MDKSA-2005:213: php";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:213 (php).



A number of vulnerabilities were discovered in PHP: An issue with
fopen_wrappers.c would not properly restrict access to other directories when
the open_basedir directive included a trailing slash (CVE-2005-3054); this
issue does not affect Corporate Server 2.1. An issue with the apache2handler
SAPI in mod_php could allow an attacker to cause a Denial of Service via the
session.save_path option in an .htaccess file or VirtualHost stanza
(CVE-2005-3319); this issue does not affect Corporate Server 2.1. A Denial of
Service vulnerability was discovered in the way that PHP processes EXIF image
data which could allow an attacker to cause PHP to crash by supplying carefully
crafted EXIF image data (CVE-2005-3353). A cross-site scripting vulnerability
was discovered in the phpinfo() function which could allow for the injection of
javascript or HTML content onto a page displaying phpinfo() output, or to steal
data such as cookies (CVE-2005-3388). A flaw in the parse_str() function could
allow for the enabling of register_globals, even if it was disabled in the PHP
configuration file (CVE-2005-3389). A vulnerability in the way that PHP
registers global variables during a file upload request could allow a remote
attacker to overwrite the $GLOBALS array which could potentially lead the
execution of arbitrary PHP commands. This vulnerability only affects systems
with register_globals enabled (CVE-2005-3390). The updated packages have been
patched to address this issue. Once the new packages have been installed, you
will need to restart your Apache server using 'service httpd restart' in order
for the new packages to take effect ('service httpd2-naat restart' for MNF2).



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:213
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
if ( rpm_check( reference:"libphp_common432-4.3.8-3.6.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php432-devel-4.3.8-3.6.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cgi-4.3.8-3.6.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cli-4.3.8-3.6.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libphp_common432-4.3.10-7.4.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php432-devel-4.3.10-7.4.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cgi-4.3.10-7.4.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cli-4.3.10-7.4.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libphp5_common5-5.0.4-9.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cgi-5.0.4-9.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cli-5.0.4-9.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-5.0.4-9.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-exif-5.0.4-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-fcgi-5.0.4-9.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"php-", release:"MDK10.1")
 || rpm_exists(rpm:"php-", release:"MDK10.2")
 || rpm_exists(rpm:"php-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3054", value:TRUE);
 set_kb_item(name:"CVE-2005-3319", value:TRUE);
 set_kb_item(name:"CVE-2005-3353", value:TRUE);
 set_kb_item(name:"CVE-2005-3388", value:TRUE);
 set_kb_item(name:"CVE-2005-3389", value:TRUE);
 set_kb_item(name:"CVE-2005-3390", value:TRUE);
}
