#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:021
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14120);
 script_bugtraq_id(8981, 9323);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0564", "CVE-2003-0594");
 
 name["english"] = "MDKSA-2004:021: mozilla";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:021 (mozilla).


A number of vulnerabilities were discovered in Mozilla 1.4:
A malicious website could gain access to a user's authentication credentials to
a proxy server.
Script.prototype.freeze/thaw could allow an attacker to run arbitrary code on
your computer.
A vulnerability was also discovered in the NSS security suite which ships with
Mozilla. The S/MIME implementation would allow remote attackers to cause a
Denial of Service and possibly execute arbitrary code via an S/MIME email
message containing certain unexpected ASN.1 constructs, which was demonstrated
using the NISCC test suite. NSS version 3.9 corrects these problems and has been
included in this package (which shipped with NSS 3.8).
Finally, Corsaire discovered that a number of HTTP user agents contained a flaw
in how they handle cookies. This flaw could allow an attacker to avoid the path
restrictions specified by a cookie's originator. According to their advisory:
'The cookie specifications detail a path argument that can be used to restrict
the areas of a host that will be exposed to a cookie. By using standard
traversal techniques this functionality can be subverted, potentially exposing
the cookie to scrutiny and use in further attacks.'
As well, a bug with Mozilla and Finnish keyboards has been corrected.
The updated packages are patched to correct these vulnerabilities.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:021
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
if ( rpm_check( reference:"libnspr4-1.4-13.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnspr4-devel-1.4-13.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnss3-1.4-13.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnss3-devel-1.4-13.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.4-13.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.4-13.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.4-13.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-enigmail-1.4-13.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-enigmime-1.4-13.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-irc-1.4-13.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.4-13.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.4-13.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-spellchecker-1.4-13.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mozilla-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0564", value:TRUE);
 set_kb_item(name:"CVE-2003-0594", value:TRUE);
}
