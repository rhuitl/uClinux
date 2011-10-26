#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:091
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21602);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-1990", "CVE-2006-1991");
 
 name["english"] = "MDKSA-2006:091: php";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:091 (php).



An integer overflow in the wordwrap() function could allow attackers

to execute arbitrary code via certain long arguments that cause a small

buffer to be allocated, triggering a heap-based buffer overflow

(CVE-2006-1990).



The substr_compare() function in PHP 5.x and 4.4.2 could allow

attackers to cause a Denial of Service (memory access violation)

via an out-of-bounds offset argument (CVE-2006-1991).



The second vulnerability only affects Mandriva Linux 2006; earlier

versions shipped with older versions of PHP that do not contain the

substr_compare() function.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:091
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
if ( rpm_check( reference:"libphp_common432-4.3.10-7.12.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php432-devel-4.3.10-7.12.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cgi-4.3.10-7.12.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cli-4.3.10-7.12.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libphp5_common5-5.0.4-9.9.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cgi-5.0.4-9.9.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cli-5.0.4-9.9.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-5.0.4-9.9.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-fcgi-5.0.4-9.9.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"php-", release:"MDK10.2")
 || rpm_exists(rpm:"php-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-1990", value:TRUE);
 set_kb_item(name:"CVE-2006-1991", value:TRUE);
}
