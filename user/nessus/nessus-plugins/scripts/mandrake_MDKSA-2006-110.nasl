#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:110
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21754);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-3082");
 
 name["english"] = "MDKSA-2006:110: gnupg";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:110 (gnupg).



A vulnerability was discovered in GnuPG 1.4.3 and 1.9.20 (and earlier)

that could allow a remote attacker to cause gpg to crash and possibly

overwrite memory via a message packet with a large length.



The updated packages have been patched to correct these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:110
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
if ( rpm_check( reference:"gnupg-1.4.2.2-0.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gnupg-1.4.2.2-0.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gnupg2-1.9.16-4.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gnupg-", release:"MDK10.2")
 || rpm_exists(rpm:"gnupg-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-3082", value:TRUE);
}
