#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:023
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20817);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-0106");
 
 name["english"] = "MDKSA-2006:023: perl-Net_SSLeay";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:023 (perl-Net_SSLeay).



Javier Fernandez-Sanguino Pena discovered that the perl Net::SSLeay module used
the file /tmp/entropy as a fallback entropy source if a proper source was not
set via the environment variable EGD_PATH. This could potentially lead to
weakened cryptographic operations if an attacker was able to provide a /tmp/
entropy file with known content. The updated packages have been patched to
correct this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:023
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the perl-Net_SSLeay package";
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
if ( rpm_check( reference:"perl-Net_SSLeay-1.25-4.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-Net_SSLeay-1.25-4.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-Net_SSLeay-1.25-4.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"perl-Net_SSLeay-", release:"MDK10.1")
 || rpm_exists(rpm:"perl-Net_SSLeay-", release:"MDK10.2")
 || rpm_exists(rpm:"perl-Net_SSLeay-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-0106", value:TRUE);
}
