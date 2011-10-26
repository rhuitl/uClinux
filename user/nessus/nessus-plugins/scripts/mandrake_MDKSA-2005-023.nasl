#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:023
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16269);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0034");
 
 name["english"] = "MDKSA-2005:023: bind";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:023 (bind).



A vulnerability was discovered in BIND version 9.3.0 where a remote attacker
may be able to cause named to exit prematurely, causing a Denial of Service due
to an incorrect assumption in the validator function authvalidated().

The updated packages have been patched to prevent this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:023
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the bind package";
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
if ( rpm_check( reference:"bind-9.3.0-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind-devel-9.3.0-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind-utils-9.3.0-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"bind-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-0034", value:TRUE);
}
