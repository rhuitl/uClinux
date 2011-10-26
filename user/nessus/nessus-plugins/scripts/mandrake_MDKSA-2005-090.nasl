#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:090
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18306);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-1194");
 
 name["english"] = "MDKSA-2005:090: nasm";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:090 (nasm).



A buffer overflow in nasm was discovered by Josh Bressers. If an attacker could
trick a user into assembling a malicious source file, they could use this
vulnerability to execute arbitrary code with the privileges of the user running
nasm.

The provided packages have been patched to correct these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:090
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the nasm package";
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
if ( rpm_check( reference:"nasm-0.98.38-1.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nasm-doc-0.98.38-1.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nasm-rdoff-0.98.38-1.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nasm-0.98.38-1.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nasm-doc-0.98.38-1.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nasm-rdoff-0.98.38-1.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nasm-0.98.39-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nasm-doc-0.98.39-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nasm-rdoff-0.98.39-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"nasm-", release:"MDK10.0")
 || rpm_exists(rpm:"nasm-", release:"MDK10.1")
 || rpm_exists(rpm:"nasm-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1194", value:TRUE);
}
