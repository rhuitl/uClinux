#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:151
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19907);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2491");
 
 name["english"] = "MDKSA-2005:151: pcre";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:151 (pcre).



Integer overflow in pcre_compile.c in Perl Compatible Regular Expressions
(PCRE) before 6.2, as used in multiple products, allows attackers to execute
arbitrary code via quantifier values in regular expressions, which leads to a
heap-based buffer overflow.

The updated packages have been patched to correct this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:151
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the pcre package";
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
if ( rpm_check( reference:"libpcre0-4.5-3.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpcre0-devel-4.5-3.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pcre-4.5-3.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpcre0-4.5-5.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpcre0-devel-4.5-5.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pcre-4.5-5.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpcre0-5.0-2.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpcre0-devel-5.0-2.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pcre-5.0-2.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"pcre-", release:"MDK10.0")
 || rpm_exists(rpm:"pcre-", release:"MDK10.1")
 || rpm_exists(rpm:"pcre-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2491", value:TRUE);
}
