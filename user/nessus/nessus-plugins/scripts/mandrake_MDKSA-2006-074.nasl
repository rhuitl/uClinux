#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:074
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21281);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0996", "CVE-2006-1494", "CVE-2006-1608");
 
 name["english"] = "MDKSA-2006:074: php";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:074 (php).



A cross-site scripting (XSS) vulnerability in phpinfo (info.c) in PHP <= 5.1.2
allows remote attackers to inject arbitrary web script or HTML via long array
variables, including (1) a large number of dimensions or (2) long values, which
prevents HTML tags from being removed. (CVE-2006-0996) Directory traversal
vulnerability in file.c in PHP <= 5.1.2 allows local users to bypass
open_basedir restrictions and allows remote attackers to create files in
arbitrary directories via the tempnam function. (CVE-2006-1494) The copy
function in file.c in PHP <= 5.1.2 allows local users to bypass safe mode and
read arbitrary files via a source argument containing a compress.zlib:// URI.
(CVE-2006-1608) Updated packages have been patched to address these issues.
After upgrading these packages, please run 'service httpd restart'.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:074
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
if ( rpm_check( reference:"libphp_common432-4.3.10-7.11.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php432-devel-4.3.10-7.11.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cgi-4.3.10-7.11.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cli-4.3.10-7.11.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libphp5_common5-5.0.4-9.7.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cgi-5.0.4-9.7.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cli-5.0.4-9.7.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-5.0.4-9.7.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-fcgi-5.0.4-9.7.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"php-", release:"MDK10.2")
 || rpm_exists(rpm:"php-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-0996", value:TRUE);
 set_kb_item(name:"CVE-2006-1494", value:TRUE);
 set_kb_item(name:"CVE-2006-1608", value:TRUE);
}
