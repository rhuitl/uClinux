#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:072
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18091);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-1018", "CVE-2004-1043", "CVE-2004-1063", "CVE-2004-1064", "CVE-2005-0524", "CVE-2005-0525", "CVE-2005-1042", "CVE-2005-1043");
 
 name["english"] = "MDKSA-2005:072: php";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:072 (php).



A number of vulnerabilities are addressed in this PHP update:

Stefano Di Paolo discovered integer overflows in PHP's pack(), unpack(), and
shmop_write() functions which could allow a malicious script to break out of
safe mode and execute arbitray code with privileges of the PHP interpreter
(CVE-2004-1018; this was previously fixed in Mandrakelinux >= 10.0 in
MDKSA-2004:151).

Stefan Esser discovered two safe mode bypasses which would allow malicious
scripts to circumvent path restrictions by using virtual_popen() with a current
directory containing shell meta- characters (CVE-2004-1063) or by creating a
specially crafted directory whose length exceeded the capacity of realpath()
(CVE-2004-1064; both of these were previously fixed in Mandrakelinux >= 10.0 in
MDKSA-2004:151).

Two Denial of Service vulnerabilities were found in the getimagesize() function
which uses the format-specific internal functions php_handle_iff() and
php_handle_jpeg() which would get stuck in infinite loops when certain
(invalid) size parameters are read from the image (CVE-2005-0524 and
CVE-2005-0525).

An integer overflow was discovered in the exif_process_IFD_TAG() function in
PHP's EXIF module. EXIF tags with a specially crafted 'Image File Directory'
(IFD) tag would cause a buffer overflow which could be exploited to execute
arbitrary code with the privileges of the PHP server (CVE-2005-1042).

Another vulnerability in the EXIF module was also discovered where headers with
a large IFD nesting level would cause an unbound recursion which would
eventually overflow the stack and cause the executed program to crash
(CVE-2004-1043).

All of these issues are addressed in the Corporate Server 2.1 packages and the
last three issues for all other platforms, which had previously included the
first two issues but had not been mentioned in MDKSA-2004:151.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:072
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the php package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"libphp_common432-4.3.4-4.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cgi-4.3.4-4.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cli-4.3.4-4.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php432-devel-4.3.4-4.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libphp_common432-4.3.8-3.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cgi-4.3.8-3.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cli-4.3.8-3.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php432-devel-4.3.8-3.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libphp_common432-4.3.10-7.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cgi-4.3.10-7.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cli-4.3.10-7.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php432-devel-4.3.10-7.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"php-", release:"MDK10.0")
 || rpm_exists(rpm:"php-", release:"MDK10.1")
 || rpm_exists(rpm:"php-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2004-1018", value:TRUE);
 set_kb_item(name:"CVE-2004-1043", value:TRUE);
 set_kb_item(name:"CVE-2004-1063", value:TRUE);
 set_kb_item(name:"CVE-2004-1064", value:TRUE);
 set_kb_item(name:"CVE-2005-0524", value:TRUE);
 set_kb_item(name:"CVE-2005-0525", value:TRUE);
 set_kb_item(name:"CVE-2005-1042", value:TRUE);
 set_kb_item(name:"CVE-2005-1043", value:TRUE);
}
