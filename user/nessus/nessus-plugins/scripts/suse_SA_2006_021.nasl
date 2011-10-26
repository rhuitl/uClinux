#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:021
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21289);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2006:021: MozillaFirefox,mozilla";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2006:021 (MozillaFirefox,mozilla).


A number of security issues have been fixed in the Mozilla browser
suite and the Mozilla Firefox browser.
These problems could be used by remote attackers to gain privileges,
gain access to confidential information or to cause denial of service
attacks.

The updates of the Firefox packages bring it up to Firefox 1.0.8 fix level.
The updates of the Mozilla suite bring it up to Mozilla 1.7.13 fix level.

Mozilla Thunderbird is also affected by some of the listed issues, but
updates will be provided later due to unrelated problems. Most of them
can be worked around by turning Java Script in Mails off (which is the
default for Thunderbird).

Full details of all issues can be found on:
http://www.mozilla.org/security/announce/

List of issues that were fixed:

MFSA 2006-25/CVE-2006-1727:
Privilege escalation through Print Preview
MFSA 2006-24/CVE-2006-1728:
Privilege escalation using crypto.generateCRMFRequest
MFSA 2006-23/CVE-2006-1729:
File stealing by changing input type
MFSA 2006-22/CVE-2006-1730:
CSS Letter-Spacing Heap Overflow Vulnerability
MFSA 2006-21/CVE-2006-0884:
Javascript execution when forwarding or replying
MFSA 2006-19/CVE-2006-1731
Cross-site scripting using .valueOf.call()
MFSA 2006-18/CVE-2006-0749
Mozilla Firefox Tag Order Vulnerability
MFSA 2006-17/CVE-2006-1732
Cross-site scripting through window.controllers
MFSA 2006-16/CVE-2006-1733
Accessing XBL compilation scope via valueOf.call()
MFSA 2006-15/CVE-2006-1734
Privilege escalation using a JavaScript functions cloned parent
MFSA 2006-14/CVE-2006-1735
Privilege escalation via XBL.method.eval
MFSA 2006-13/CVE-2006-1736
Downloading executables with 'Save Image As...'
MFSA 2006-12/CVE-2006-1740
Secure-site spoof (requires security warning dialog)
MFSA 2006-11/CVE-2006-1739,CVE-2006-1737,CVE-2006-1738,CVE-2006-1790
Crashes with evidence of memory corruption (rv:1.8)
MFSA 2006-10/CVE-2006-1742
JavaScript garbage-collection hazard audit
MFSA 2006-09/CVE-2006-1741
Cross-site JavaScript injection using event handlers

We wish to thank the Mozilla Developers and the various bug reporters
for reporting and fixing those issues.


Solution : http://www.suse.de/security/advisories/2006_04_20.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the MozillaFirefox,mozilla package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"MozillaFirefox-1.0.8-0.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-1.0.8-0.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.11-9.5", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-calendar-1.7.11-9.5", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.11-9.5", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.11-9.5", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-irc-1.7.11-9.5", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.11-9.5", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-spellchecker-1.7.11-9.5", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-venkman-1.7.11-9.5", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-1.0.8-0.2", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-1.0.8-0.2", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.8-5.20", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-calendar-1.7.8-5.20", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-cs-1.7.5-4.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-deat-1.7.6-0.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.8-5.20", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.8-5.20", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-hu-1.78-0.7", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-irc-1.7.8-5.20", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-ja-1.7.7-0.7", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-ko-1.75-0.7", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.8-5.20", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-spellchecker-1.7.8-5.20", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-venkman-1.7.8-5.20", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-1.0.8-0.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-1.0.8-0.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"epiphany-1.2.10-0.6", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"epiphany-doc-1.2.10-0.6", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"epiphany-extensions-0.8.2-4.7", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"epiphany-extensions-devel-0.8.2-4.7", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"galeon-1.3.19-6.3", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.2-17.17", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-calendar-1.7.2-17.17", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.2-17.17", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.2-17.17", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-irc-1.7.2-17.17", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.2-17.17", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-spellchecker-1.7.2-17.17", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-venkman-1.7.2-17.17", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-1.0.8-0.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-1.0.8-0.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.5-17.10", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-calendar-1.7.5-17.10", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.5-17.10", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.5-17.10", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-irc-1.7.5-17.10", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.5-17.10", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-spellchecker-1.7.5-17.10", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-venkman-1.7.5-17.10", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
