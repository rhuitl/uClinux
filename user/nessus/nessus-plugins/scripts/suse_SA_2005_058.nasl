#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:058
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19937);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "SUSE-SA:2005:058: mozilla,MozillaFirefox";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:058 (mozilla,MozillaFirefox).


The web browsers Mozilla and Mozilla Firefox have been updated to
contain fixes for the vulnerabilities fixed in:

- Mozilla browser suite version 1.7.12
- Mozilla Firefox version 1.0.7

The security problems with their corresponding Mitre CVE ID are:
- CVE-2005-2701: Heap overrun in XBM image processing
- CVE-2005-2702: Crash on 'zero-width non-joiner' sequence
- CVE-2005-2703: XMLHttpRequest header spoofing
- CVE-2005-2704: Object spoofing using XBL <implements>
- CVE-2005-2705: Javascript integer overflow
- CVE-2005-2706: Privilege escalation using about: scheme
- CVE-2005-2707: Chrome window spoofing


Solution : http://www.suse.de/security/advisories/2005_58_mozilla.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mozilla,MozillaFirefox package";
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
if ( rpm_check( reference:"MozillaFirefox-1.0.7-0.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-1.0.7-0.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.11-9.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-calendar-1.7.11-9.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.11-9.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.11-9.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-irc-1.7.11-9.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.11-9.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-spellchecker-1.7.11-9.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-venkman-1.7.11-9.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirebird-1.0.7-2", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.8-22", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-calendar-1.7.8-22", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-cs-1.7.5-8", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-deat-1.7.6-5", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.8-22", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.8-22", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-hu-1.78-6", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-irc-1.7.8-22", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.8-22", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-spellchecker-1.7.8-22", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-venkman-1.7.8-22", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-1.0.7-0.2", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-1.0.7-0.2", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.8-5.13", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-calendar-1.7.8-5.13", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-cs-1.7.5-4.5", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-deat-1.7.6-0.5", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.8-5.13", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.8-5.13", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-hu-1.78-0.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-irc-1.7.8-5.13", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-ja-1.7.7-0.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-ko-1.75-0.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.8-5.13", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-spellchecker-1.7.8-5.13", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-venkman-1.7.8-5.13", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-1.0.7-0.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-1.0.7-0.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"epiphany-1.2.10-0.4", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"epiphany-doc-1.2.10-0.4", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"epiphany-extensions-0.8.2-4.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"epiphany-extensions-devel-0.8.2-4.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"galeon-1.3.19-6.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.2-17.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-calendar-1.7.2-17.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.2-17.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.2-17.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-irc-1.7.2-17.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.2-17.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-spellchecker-1.7.2-17.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-venkman-1.7.2-17.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-1.0.7-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-1.0.7-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.5-17.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-calendar-1.7.5-17.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.5-17.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.5-17.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-irc-1.7.5-17.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.5-17.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-spellchecker-1.7.5-17.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-venkman-1.7.5-17.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
