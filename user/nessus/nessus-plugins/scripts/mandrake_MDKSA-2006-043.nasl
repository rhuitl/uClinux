#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:043
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20942);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0455");
 
 name["english"] = "MDKSA-2006:043: gnupg";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:043 (gnupg).



Tavis Ormandy discovered it is possible to make gpg incorrectly return success
when verifying an invalid signature file. The updated packages have been
patched to address this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:043
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gnupg package";
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
if ( rpm_check( reference:"gnupg-1.2.4-1.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gnupg-1.4.0-4.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gnupg-1.4.2-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gnupg-", release:"MDK10.1")
 || rpm_exists(rpm:"gnupg-", release:"MDK10.2")
 || rpm_exists(rpm:"gnupg-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-0455", value:TRUE);
}
