#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:151
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15998);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-1019", "CVE-2004-1065");
 
 name["english"] = "MDKSA-2004:151: php";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:151 (php).



A number of vulnerabilities in PHP versions prior to 4.3.10 were discovered by
Stefan Esser. Some of these vulnerabilities were not deemed to be severe enough
to warrant CVE names, however the packages provided, with the exception of the
Corporate Server 2.1 packages, include fixes for all of the vulnerabilities,
thanks to the efforts of the OpenPKG team who extracted and backported the
fixes.

The vulnerabilities fixed in all provided packages include a fix for a possible
information disclosure, double free, and negative reference index array
underflow in deserialization code (CVE-2004-1019). As well, the exif_read_data
() function suffers from an overflow on a long sectionname; this vulnerability
was discovered by Ilia Alshanetsky (CVE-2004-1065).

The other fixes that appear in Mandrakelinux 9.2 and newer packages include a
fix for out of bounds memory write access in shmop_write() and integer overflow
/underflows in the pack() and unpack() functions. The addslashes() function did
not properly escape '



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:151
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
if ( rpm_check( reference:"libphp_common432-4.3.4-4.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cgi-4.3.4-4.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cli-4.3.4-4.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php432-devel-4.3.4-4.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libphp_common432-4.3.8-3.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cgi-4.3.8-3.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cli-4.3.8-3.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php432-devel-4.3.8-3.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libphp_common432-4.3.3-2.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cgi-4.3.3-2.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cli-4.3.3-2.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php432-devel-4.3.3-2.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"php-", release:"MDK10.0")
 || rpm_exists(rpm:"php-", release:"MDK10.1")
 || rpm_exists(rpm:"php-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-1019", value:TRUE);
 set_kb_item(name:"CVE-2004-1065", value:TRUE);
}
