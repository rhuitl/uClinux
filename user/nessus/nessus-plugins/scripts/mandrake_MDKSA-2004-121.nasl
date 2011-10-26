#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:121
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15601);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0974");
 
 name["english"] = "MDKSA-2004:121: netatalk";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:121 (netatalk).



The etc2ps.sh script, part of the netatalk package, creates files in /tmp with
predicatable names which could allow a local attacker to use symbolic links to
point to a valid file on the filesystem which could lead to the overwriting of
arbitrary files if etc2ps.sh is executed by someone with enough privilege.

The updated packages are patched to prevent this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:121
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the netatalk package";
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
if ( rpm_check( reference:"netatalk-1.6.4-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netatalk-devel-1.6.4-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netatalk-2.0-0beta2.3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netatalk-devel-2.0-0beta2.3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netatalk-1.6.3-4.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netatalk-devel-1.6.3-4.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"netatalk-", release:"MDK10.0")
 || rpm_exists(rpm:"netatalk-", release:"MDK10.1")
 || rpm_exists(rpm:"netatalk-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0974", value:TRUE);
}
