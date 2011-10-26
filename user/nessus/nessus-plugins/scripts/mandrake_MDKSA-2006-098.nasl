#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:098
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21670);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-2313", "CVE-2006-2314");
 
 name["english"] = "MDKSA-2006:098: postgresql";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:098 (postgresql).



PostgreSQL 8.1.x before 8.1.4, 8.0.x before 8.0.8, 7.4.x before 7.4.13,

7.3.x before 7.3.15, and earlier versions allows context-dependent

attackers to bypass SQL injection protection methods in applications

via invalid encodings of multibyte characters, aka one variant of

'Encoding-Based SQL Injection.' (CVE-2006-2313)



PostgreSQL 8.1.x before 8.1.4, 8.0.x before 8.0.8, 7.4.x before 7.4.13,

7.3.x before 7.3.15, and earlier versions allows context-dependent

attackers to bypass SQL injection protection methods in applications

that use multibyte encodings that allow the '' (backslash) byte 0x5c to

be the trailing byte of a multibyte character, such as SJIS, BIG5, GBK,

GB18030, and UHC, which cannot be handled correctly by a client that does

not understand multibyte encodings, aka a second variant of 'Encoding-Based

SQL Injection.' NOTE: it could be argued that this is a class of issue

related to interaction errors between the client and PostgreSQL, but a

CVE has been assigned since PostgreSQL is treating this as a preventative

measure against this class of problem. (CVE-2006-2314)



Packages have been patched or updated to correct these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:098
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the postgresql package";
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
if ( rpm_check( reference:"libecpg5-8.0.8-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libecpg5-devel-8.0.8-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpq4-8.0.8-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpq4-devel-8.0.8-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-8.0.8-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-8.0.8-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-devel-8.0.8-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-docs-8.0.8-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-jdbc-8.0.8-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-pl-8.0.8-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-plperl-8.0.8-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-plpgsql-8.0.8-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-plpython-8.0.8-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-pltcl-8.0.8-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-server-8.0.8-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-test-8.0.8-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libecpg5-8.0.8-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libecpg5-devel-8.0.8-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpq4-8.0.8-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpq4-devel-8.0.8-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-8.0.8-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-8.0.8-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-devel-8.0.8-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-docs-8.0.8-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-jdbc-8.0.8-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-pl-8.0.8-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-plperl-8.0.8-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-plpgsql-8.0.8-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-plpython-8.0.8-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-pltcl-8.0.8-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-server-8.0.8-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-test-8.0.8-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"postgresql-", release:"MDK10.2")
 || rpm_exists(rpm:"postgresql-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-2313", value:TRUE);
 set_kb_item(name:"CVE-2006-2314", value:TRUE);
}
