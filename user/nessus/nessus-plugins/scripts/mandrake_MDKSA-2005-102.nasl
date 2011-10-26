#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:102
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18499);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-1686");
 
 name["english"] = "MDKSA-2005:102: gedit";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:102 (gedit).



A vulnerability was discovered in gEdit where it was possible for an attacker
to create a file with a carefully crafted name which, when opened, executed
arbitrary code on the victim's computer. It is highly unlikely that a user
would open such a file, due to the file name, but could possibly be tricked
into opening it.

The updated packages have been patched to correct this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:102
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gedit package";
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
if ( rpm_check( reference:"gedit-2.6.2-4.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gedit-devel-2.6.2-4.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gedit-2.8.3-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gedit-devel-2.8.3-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gedit-", release:"MDK10.1")
 || rpm_exists(rpm:"gedit-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1686", value:TRUE);
}
