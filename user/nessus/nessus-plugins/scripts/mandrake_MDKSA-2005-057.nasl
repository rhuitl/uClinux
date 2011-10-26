#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:057
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17334);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0366");
 
 name["english"] = "MDKSA-2005:057: gnupg";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:057 (gnupg).



The OpenPGP protocol is vulnerable to a timing-attack in order to gain plain
text from cipher text. The timing difference appears as a side effect of the
so-called 'quick scan' and is only exploitable on systems that accept an
arbitrary amount of cipher text for automatic decryption.

The updated packages have been patched to disable the quick check for all
public key-encrypted messages and files.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:057
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gnupg package";
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
if ( rpm_check( reference:"gnupg-1.2.4-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gnupg-1.2.4-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gnupg-1.2.3-3.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gnupg-", release:"MDK10.0")
 || rpm_exists(rpm:"gnupg-", release:"MDK10.1")
 || rpm_exists(rpm:"gnupg-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2005-0366", value:TRUE);
}
