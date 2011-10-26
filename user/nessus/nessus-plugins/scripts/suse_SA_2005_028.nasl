#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:028
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18154);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1155", "CVE-2005-1157", "CVE-2005-1158", "CVE-2005-1159", "CVE-2005-1160");
 
 name["english"] = "SUSE-SA:2005:028: Mozilla. Mozilla Firefox";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:028 (Mozilla. Mozilla Firefox).


Several problems have been fixed with the security update releases
of the Mozilla Firefox 1.0.3 web browser and the Mozilla Suite 1.7.7.

This security update contains those security fixes. The Firefox
packages have been directly upgraded to the version 1.0.3, for
the Mozilla Suite packages the fixes up to version 1.7.7 have been
back ported.

Updates are currently provided for:

Mozilla Firefox: SUSE Linux 9.0 up to 9.3, Novell Linux Desktop 9
Mozilla Suite: SUSE Linux 9.2 and 9.3

Fixes of the Mozilla Suite for older products (SUSE Linux 8.2 - 9.1, 
SUSE Linux Enterprise Server 8 and 9, SUSE Linux Desktop 1.0) are
being worked on.

Following security issues have been fixed:
- MFSA 2005-33,CVE-2005-0989:
A flaw in the Javascript regular expression handling of Mozilla
based browser can lead to disclosure of browser memory, potentially
exposing private data from web pages viewed or passwords or
similar data sent to other web pages.  This flaw could also crash
the browser.

- MFSA 2005-34,CVE-2005-0752:
With manual Plugin install it was possible for the Plugin to
execute javascript code with the installing users privileges.

- MFSA 2005-35,CVE-2005-1153:
Showing blocked javascript: pop up uses wrong privilege context,
this could be used for a privilege escalation (installing malicious
plugins).

- MFSA 2005-36,CVE-2005-1154:
Cross-site scripting through global scope pollution, this could
lead to an attacker being able to run code in foreign websites
context, potentially sniffing information or performing actions
in that context.

- MFSA 2005-37,CVE-2005-1155,'firelinking':
Code execution through javascript: favicons, which could be used
for a privilege escalation.

- MFSA 2005-38,CVE-2005-1157,CVE-2005-1156,'firesearching':
Search Plugin cross-site scripting.

- MFSA 2005-39,CVE-2005-1158:
Arbitrary code execution from Firefox sidebar panel II.

- MFSA 2005-40,CVE-2005-1159:
Missing Install object instance checks.

- MFSA 2005-41,CVE-2005-1160:
Privilege escalation via DOM property overrides.


Solution : http://www.suse.de/security/advisories/2005_28_mozilla_firefox.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the Mozilla. Mozilla Firefox package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"MozillaFirebird-1.0.3-3", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-1.0.3-0.5", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-1.0.3-1.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.2-17.9", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-calendar-1.7.2-17.9", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.2-17.9", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.2-17.9", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-irc-1.7.2-17.9", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.2-17.9", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-spellchecker-1.7.2-17.9", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-venkman-1.7.2-17.9", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-1.0.3-1.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-1.0.3-1.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.5-17.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-calendar-1.7.5-17.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.5-17.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.5-17.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-irc-1.7.5-17.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.5-17.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-spellchecker-1.7.5-17.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-venkman-1.7.5-17.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"Mozilla. Mozilla Firefox-", release:"SUSE9.0")
 || rpm_exists(rpm:"Mozilla. Mozilla Firefox-", release:"SUSE9.1")
 || rpm_exists(rpm:"Mozilla. Mozilla Firefox-", release:"SUSE9.2")
 || rpm_exists(rpm:"Mozilla. Mozilla Firefox-", release:"SUSE9.3") )
{
 set_kb_item(name:"CVE-2005-0752", value:TRUE);
 set_kb_item(name:"CVE-2005-0989", value:TRUE);
 set_kb_item(name:"CVE-2005-1153", value:TRUE);
 set_kb_item(name:"CVE-2005-1154", value:TRUE);
 set_kb_item(name:"CVE-2005-1155", value:TRUE);
 set_kb_item(name:"CVE-2005-1157", value:TRUE);
 set_kb_item(name:"CVE-2005-1158", value:TRUE);
 set_kb_item(name:"CVE-2005-1159", value:TRUE);
 set_kb_item(name:"CVE-2005-1160", value:TRUE);
}
