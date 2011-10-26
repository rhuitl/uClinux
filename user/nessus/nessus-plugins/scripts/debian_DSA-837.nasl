# This script was automatically generated from the dsa-837
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Tom Ferris discovered a bug in the IDN hostname handling of Mozilla
Firefox, which is also present in the other browsers from the same
family that allows remote attackers to cause a denial of service and
possibly execute arbitrary code via a hostname with dashes.
For the stable distribution (sarge) this problem has been fixed in
version 1.0.4-2sarge4.
For the unstable distribution (sid) this problem has been fixed in
version 1.0.6-5.
We recommend that you upgrade your mozilla-firefox package.


Solution : http://www.debian.org/security/2005/dsa-837
Risk factor : High';

if (description) {
 script_id(19806);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "837");
 script_cve_id("CVE-2005-2871");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA837] DSA-837-1 mozilla-firefox");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-837-1 mozilla-firefox");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mozilla-firefox', release: '', reference: '1.0.6-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox is vulnerable in Debian .\nUpgrade to mozilla-firefox_1.0.6-5\n');
}
if (deb_check(prefix: 'mozilla-firefox', release: '3.1', reference: '1.0.4-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox is vulnerable in Debian 3.1.\nUpgrade to mozilla-firefox_1.0.4-2sarge4\n');
}
if (deb_check(prefix: 'mozilla-firefox-dom-inspector', release: '3.1', reference: '1.0.4-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox-dom-inspector is vulnerable in Debian 3.1.\nUpgrade to mozilla-firefox-dom-inspector_1.0.4-2sarge4\n');
}
if (deb_check(prefix: 'mozilla-firefox-gnome-support', release: '3.1', reference: '1.0.4-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox-gnome-support is vulnerable in Debian 3.1.\nUpgrade to mozilla-firefox-gnome-support_1.0.4-2sarge4\n');
}
if (deb_check(prefix: 'mozilla-firefox', release: '3.1', reference: '1.0.4-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox is vulnerable in Debian sarge.\nUpgrade to mozilla-firefox_1.0.4-2sarge4\n');
}
if (w) { security_hole(port: 0, data: desc); }
