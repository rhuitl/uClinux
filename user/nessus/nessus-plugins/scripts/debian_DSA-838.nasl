# This script was automatically generated from the dsa-838
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Multiple security vulnerabilities have been identified in the
mozilla-firefox web browser. These vulnerabilities could allow an
attacker to execute code on the victim\'s machine via specially crafted
network resources.
	Heap overrun in XBM image processing
	Denial of service (crash) and possible execution of arbitrary
	code via Unicode sequences with "zero-width non-joiner"
	characters.
	XMLHttpRequest header spoofing
	Object spoofing using XBL <implements>
	JavaScript integer overflow
	Privilege escalation using about: scheme
	Chrome window spoofing allowing windows to be created without
	UI components such as a URL bar or status bar that could be
	used to carry out phishing attacks
For the stable distribution (sarge), these problems have been fixed in
version 1.0.4-2sarge5.
For the unstable distribution (sid), these problems have been fixed in
version 1.0.7-1.
We recommend that you upgrade your mozilla-firefox package.


Solution : http://www.debian.org/security/2005/dsa-838
Risk factor : High';

if (description) {
 script_id(19807);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "838");
 script_cve_id("CVE-2005-2701", "CVE-2005-2702", "CVE-2005-2703", "CVE-2005-2704", "CVE-2005-2705", "CVE-2005-2706", "CVE-2005-2707");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA838] DSA-838-1 mozilla-firefox");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-838-1 mozilla-firefox");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mozilla-firefox', release: '', reference: '1.0.7-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox is vulnerable in Debian .\nUpgrade to mozilla-firefox_1.0.7-1\n');
}
if (deb_check(prefix: 'mozilla-firefox', release: '3.1', reference: '1.0.4-2sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox is vulnerable in Debian 3.1.\nUpgrade to mozilla-firefox_1.0.4-2sarge5\n');
}
if (deb_check(prefix: 'mozilla-firefox-dom-inspector', release: '3.1', reference: '1.0.4-2sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox-dom-inspector is vulnerable in Debian 3.1.\nUpgrade to mozilla-firefox-dom-inspector_1.0.4-2sarge5\n');
}
if (deb_check(prefix: 'mozilla-firefox-gnome-support', release: '3.1', reference: '1.0.4-2sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox-gnome-support is vulnerable in Debian 3.1.\nUpgrade to mozilla-firefox-gnome-support_1.0.4-2sarge5\n');
}
if (deb_check(prefix: 'mozilla-firefox', release: '3.1', reference: '1.0.4-2sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox is vulnerable in Debian sarge.\nUpgrade to mozilla-firefox_1.0.4-2sarge5\n');
}
if (w) { security_hole(port: 0, data: desc); }
