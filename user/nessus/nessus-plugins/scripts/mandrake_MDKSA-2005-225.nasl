#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:225
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20456);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3962");
 
 name["english"] = "MDKSA-2005:225: perl";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:225 (perl).



Jack Louis discovered a new way to exploit format string errors in the Perl
programming language that could lead to the execution of arbitrary code. The
updated packages are patched to close the particular exploit vector in Perl
itself, to mitigate the risk of format string programming errors, however it
does not fix problems that may exist in particular pieces of software written
in Perl.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:225
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the perl package";
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
if ( rpm_check( reference:"perl-5.8.5-3.5.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-base-5.8.5-3.5.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-devel-5.8.5-3.5.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-doc-5.8.5-3.5.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-5.8.6-6.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-base-5.8.6-6.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-devel-5.8.6-6.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-doc-5.8.6-6.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-5.8.7-3.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-base-5.8.7-3.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-devel-5.8.7-3.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-doc-5.8.7-3.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-suid-5.8.7-3.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"perl-", release:"MDK10.1")
 || rpm_exists(rpm:"perl-", release:"MDK10.2")
 || rpm_exists(rpm:"perl-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3962", value:TRUE);
}
