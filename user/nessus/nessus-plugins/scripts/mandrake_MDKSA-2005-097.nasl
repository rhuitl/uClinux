#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:097
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18435);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-1377");
 
 name["english"] = "MDKSA-2005:097: a2ps";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:097 (a2ps).



The fixps and psmandup scripts, part of the a2ps package, are vulnerable to
symlink attacks which could allow a local attacker to overwrite arbitrary
files. The updated packages have been patched to correct the problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:097
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the a2ps package";
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
if ( rpm_check( reference:"a2ps-4.13b-5.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"a2ps-devel-4.13b-5.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"a2ps-static-devel-4.13b-5.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"a2ps-4.13b-6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"a2ps-devel-4.13b-6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"a2ps-static-devel-4.13b-6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"a2ps-", release:"MDK10.1")
 || rpm_exists(rpm:"a2ps-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2004-1377", value:TRUE);
}
