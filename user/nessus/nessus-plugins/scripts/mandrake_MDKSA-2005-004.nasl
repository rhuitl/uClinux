#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:004
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16117);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "MDKSA-2005:004: nasm";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:004 (nasm).



A buffer overflow in nasm was discovered by Jonathan Rockway. This
vulnerability could lead to the execution of arbitrary code when compiling a
malicious assembler source file.

The updated packages are patched to correct the problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:004
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
if ( rpm_check( reference:"nasm-0.98.38-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nasm-doc-0.98.38-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nasm-rdoff-0.98.38-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nasm-0.98.38-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nasm-doc-0.98.38-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nasm-rdoff-0.98.38-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
