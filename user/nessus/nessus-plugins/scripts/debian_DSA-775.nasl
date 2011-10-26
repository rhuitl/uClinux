# This script was automatically generated from the dsa-775
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability has been discovered in Mozilla and Mozilla Firefox
that allows remote attackers to inject arbitrary Javascript from one
page into the frameset of another site.  Thunderbird is not affected
by this and Galeon will be automatically fixed as it uses Mozilla
components.
The old stable distribution (woody) does not contain Mozilla Firefox
packages.
For the stable distribution (sarge) this problem has been fixed in
version 1.0.4-2sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 1.0.6-1.
We recommend that you upgrade your mozilla-firefox package.


Solution : http://www.debian.org/security/2005/dsa-775
Risk factor : High';

if (description) {
 script_id(19431);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "775");
 script_cve_id("CVE-2004-0718", "CVE-2005-1937");
 script_bugtraq_id(14242);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA775] DSA-775-1 mozilla-firefox");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-775-1 mozilla-firefox");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mozilla', release: '', reference: '1.0.6-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla is vulnerable in Debian .\nUpgrade to mozilla_1.0.6-1\n');
}
if (deb_check(prefix: 'mozilla-firefox', release: '3.1', reference: '1.0.4-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox is vulnerable in Debian 3.1.\nUpgrade to mozilla-firefox_1.0.4-2sarge1\n');
}
if (deb_check(prefix: 'mozilla-firefox-dom-inspector', release: '3.1', reference: '1.0.4-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox-dom-inspector is vulnerable in Debian 3.1.\nUpgrade to mozilla-firefox-dom-inspector_1.0.4-2sarge1\n');
}
if (deb_check(prefix: 'mozilla-firefox-gnome-support', release: '3.1', reference: '1.0.4-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox-gnome-support is vulnerable in Debian 3.1.\nUpgrade to mozilla-firefox-gnome-support_1.0.4-2sarge1\n');
}
if (deb_check(prefix: 'mozilla', release: '3.1', reference: '1.0.4-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla is vulnerable in Debian sarge.\nUpgrade to mozilla_1.0.4-2sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
