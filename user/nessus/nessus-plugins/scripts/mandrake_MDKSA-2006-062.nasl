#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:062
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21177);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-1550");
 
 name["english"] = "MDKSA-2006:062: dia";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:062 (dia).



Three buffer overflows were discovered by infamous41md in dia's xfig import
code. This could allow for user-complicit attackers to have an unknown impact
via a crafted xfig file, possibly involving an invalid color index, number of
points, or depth. Updated packages have been patched to correct this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:062
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the dia package";
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
if ( rpm_check( reference:"dia-0.94-6.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"dia-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-1550", value:TRUE);
}
