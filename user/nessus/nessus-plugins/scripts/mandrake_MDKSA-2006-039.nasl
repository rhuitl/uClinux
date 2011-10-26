#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:039
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20897);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0645");
 
 name["english"] = "MDKSA-2006:039: gnutls";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:039 (gnutls).



Evgeny Legerov discovered cases of possible out-of-bounds access in the DER
decoding schemes of libtasn1, when provided with invalid input. This library is
bundled with gnutls. The provided packages have been patched to correct these
issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:039
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gnutls package";
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
if ( rpm_check( reference:"gnutls-1.0.13-1.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgnutls11-1.0.13-1.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgnutls11-devel-1.0.13-1.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gnutls-1.0.23-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgnutls11-1.0.23-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgnutls11-devel-1.0.23-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gnutls-1.0.25-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgnutls11-1.0.25-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgnutls11-devel-1.0.25-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gnutls-", release:"MDK10.1")
 || rpm_exists(rpm:"gnutls-", release:"MDK10.2")
 || rpm_exists(rpm:"gnutls-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-0645", value:TRUE);
}
