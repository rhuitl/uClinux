#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:194
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20122);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2933");
 
 name["english"] = "MDKSA-2005:194: php-imap";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:194 (php-imap).



'infamous41md' discovered a buffer overflow in uw-imap, the University of
Washington's IMAP Server that allows attackers to execute arbitrary code.
php-imap is compiled against the static c-client libs from imap. These packages
have been recompiled against the updated imap development packages.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:194
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the php-imap package";
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
if ( rpm_check( reference:"php-imap-4.3.8-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.3.10-6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-imap-5.0.4-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"php-imap-", release:"MDK10.1")
 || rpm_exists(rpm:"php-imap-", release:"MDK10.2")
 || rpm_exists(rpm:"php-imap-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-2933", value:TRUE);
}
