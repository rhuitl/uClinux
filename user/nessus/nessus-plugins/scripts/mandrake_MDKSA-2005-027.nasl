#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:027
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16293);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-1264");
 
 name["english"] = "MDKSA-2005:027: chbg";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:027 (chbg).



A vulnerability in chbg was discovered by Danny Lungstrom. A
maliciously-crafted configuration/scenario file could overflow a buffer leading
to the potential execution of arbitrary code.

The updated packages are patched to prevent the problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:027
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the chbg package";
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
if ( rpm_check( reference:"chbg-1.5-8.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"chbg-1.5-8.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"chbg-", release:"MDK10.0")
 || rpm_exists(rpm:"chbg-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2004-1264", value:TRUE);
}
