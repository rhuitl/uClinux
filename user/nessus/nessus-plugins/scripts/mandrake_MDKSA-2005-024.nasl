#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:024
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16290);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0102");
 
 name["english"] = "MDKSA-2005:024: evolution";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:024 (evolution).



Max Vozeler discovered an integer overflow in the camel-lock-helper
application. This application is installed setgid mail by default. A local
attacker could exploit this to execute malicious code with the privileges of
the 'mail' group; likewise a remote attacker could setup a malicious POP server
to execute arbitrary code when an Evolution user connects to it.

The updated packages have been patched to prevent this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:024
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the evolution package";
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
if ( rpm_check( reference:"evolution-1.4.6-5.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"evolution-devel-1.4.6-5.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"evolution-pilot-1.4.6-5.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"evolution-2.0.3-1.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"evolution-devel-2.0.3-1.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"evolution-pilot-2.0.3-1.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"evolution-", release:"MDK10.0")
 || rpm_exists(rpm:"evolution-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-0102", value:TRUE);
}
