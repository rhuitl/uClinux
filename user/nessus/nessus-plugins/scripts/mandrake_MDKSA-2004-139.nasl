#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:139
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15836);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-1011", "CVE-2004-1012", "CVE-2004-1013", "CVE-2004-1015");
 
 name["english"] = "MDKSA-2004:139: cyrus-imapd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:139 (cyrus-imapd).



A number of vulnerabilities in the Cyrus-IMAP server were found by Stefan
Esser. Due to insufficient checking within the argument parser of the 'partial'
and 'fetch' commands, a buffer overflow could be exploited to execute arbitrary
attacker-supplied code. Another exploitable buffer overflow could be triggered
in situations when memory allocation files.

The provided packages have been patched to prevent these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:139
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cyrus-imapd package";
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
if ( rpm_check( reference:"cyrus-imapd-2.1.16-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-devel-2.1.16-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-murder-2.1.16-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-utils-2.1.16-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-Cyrus-2.1.16-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-2.2.8-4.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-devel-2.2.8-4.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-murder-2.2.8-4.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-nntp-2.2.8-4.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-utils-2.2.8-4.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-Cyrus-2.2.8-4.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cyrus-imapd-", release:"MDK10.0")
 || rpm_exists(rpm:"cyrus-imapd-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2004-1011", value:TRUE);
 set_kb_item(name:"CVE-2004-1012", value:TRUE);
 set_kb_item(name:"CVE-2004-1013", value:TRUE);
 set_kb_item(name:"CVE-2004-1015", value:TRUE);
}
