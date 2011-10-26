#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:107
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15521);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0902", "CVE-2004-0903", "CVE-2004-0904", "CVE-2004-0905", "CVE-2004-0908");
 
 name["english"] = "MDKSA-2004:107: mozilla";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:107 (mozilla).


A number of vulnerabilities were fixed in mozilla 1.7.3, the following of which
have been backported to mozilla packages for Mandrakelinux 10.0:
- 'Send page' heap overrun - javascript clipboard access - buffer overflow when
displaying VCard - BMP integer overflow - javascript: link dragging - Malicious
POP3 server III
The details of all of these vulnerabilities are available from the Mozilla
website.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:107
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mozilla package";
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
if ( rpm_check( reference:"libnspr4-1.6-12.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnspr4-devel-1.6-12.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnss3-1.6-12.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnss3-devel-1.6-12.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.6-12.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.6-12.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-enigmail-1.6-12.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-enigmime-1.6-12.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-irc-1.6-12.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.6-12.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.6-12.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-spellchecker-1.6-12.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mozilla-", release:"MDK10.0") )
{
 set_kb_item(name:"CVE-2004-0902", value:TRUE);
 set_kb_item(name:"CVE-2004-0903", value:TRUE);
 set_kb_item(name:"CVE-2004-0904", value:TRUE);
 set_kb_item(name:"CVE-2004-0905", value:TRUE);
 set_kb_item(name:"CVE-2004-0908", value:TRUE);
}
