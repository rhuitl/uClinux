#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:155
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19911);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2491");
 
 name["english"] = "MDKSA-2005:155: apache2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:155 (apache2).



Integer overflow in pcre_compile.c in Perl Compatible Regular Expressions
(PCRE) before 6.2, as used in multiple products, allows attackers to execute
arbitrary code via quantifier values in regular expressions, which leads to a
heap-based buffer overflow.

The apache2 packages, as shipped, were built using a private copy of pcre.

The updated packages have been rebuilt against the system pcre libs to correct
this problem. 10.1 and 10.2/LE2005 are already built against the system pcre.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:155
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the apache2 package";
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
if ( rpm_check( reference:"apache2-2.0.48-6.10.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-common-2.0.48-6.10.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-devel-2.0.48-6.10.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-manual-2.0.48-6.10.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_cache-2.0.48-6.10.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_dav-2.0.48-6.10.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_deflate-2.0.48-6.10.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_disk_cache-2.0.48-6.10.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_file_cache-2.0.48-6.10.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_ldap-2.0.48-6.10.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_mem_cache-2.0.48-6.10.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_proxy-2.0.48-6.10.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_ssl-2.0.48-6.10.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-modules-2.0.48-6.10.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-source-2.0.48-6.10.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libapr0-2.0.48-6.10.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"apache2-", release:"MDK10.0") )
{
 set_kb_item(name:"CVE-2005-2491", value:TRUE);
}
