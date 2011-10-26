#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:159
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19914);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2101");
 
 name["english"] = "MDKSA-2005:159: kdeedu";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:159 (kdeedu).



Ben Burton notified the KDE security team about several tempfile handling
related vulnerabilities in langen2kvtml, a conversion script for kvoctrain.
This vulnerability was initially discovered by Javier Fernández-Sanguino Peña.

The script uses known filenames in /tmp which allow an local attacker to
overwrite files writeable by the user (manually) invoking the conversion
script.

The updated packages have been patched to correct this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:159
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdeedu package";
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
if ( rpm_check( reference:"kdeedu-3.2.3-7.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdeedu1-3.2.3-7.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdeedu1-devel-3.2.3-7.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdeedu-3.3.2-9.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdeedu1-3.3.2-9.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdeedu1-devel-3.3.2-9.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kdeedu-", release:"MDK10.1")
 || rpm_exists(rpm:"kdeedu-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2101", value:TRUE);
}
