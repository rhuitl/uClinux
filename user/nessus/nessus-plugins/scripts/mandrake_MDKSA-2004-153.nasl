#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:153
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16015);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0548");
 
 name["english"] = "MDKSA-2004:153: aspell";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:153 (aspell).



A vulnerability was discovered in the aspell word-list-compress utility that
can allow an attacker to execute arbitrary code.

The updated packages have been patched to correct this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:153
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the aspell package";
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
if ( rpm_check( reference:"aspell-0.50.4.1-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libaspell15-0.50.4.1-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libaspell15-devel-0.50.4.1-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"aspell-0.50.5-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libaspell15-0.50.5-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libaspell15-devel-0.50.5-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"aspell-", release:"MDK10.0")
 || rpm_exists(rpm:"aspell-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2004-0548", value:TRUE);
}
