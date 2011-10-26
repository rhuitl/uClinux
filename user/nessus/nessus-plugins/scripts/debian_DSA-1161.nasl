# This script was automatically generated from the dsa-1161
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The latest security updates of Mozilla Firefox introduced a regression
that led to a disfunctional attachment panel which warrants a
correction to fix this issue. For reference please find below the
original advisory text:
Several security related problems have been discovered in Mozilla and
derived products like Mozilla Firefox.  The Common Vulnerabilities and
Exposures project identifies the following vulnerabilities:
    The Javascript engine might allow remote attackers to execute
    arbitrary code.  [MFSA-2006-50]
    Multiple integer overflows in the Javascript engine might allow
    remote attackers to execute arbitrary code.  [MFSA-2006-50]
    Specially crafted Javascript allows remote attackers to execute
    arbitrary code.  [MFSA-2006-51]
    Remote Proxy AutoConfig (PAC) servers could execute code with elevated
    privileges via a specially crafted PAC script.  [MFSA-2006-52]
    Scripts with the UniversalBrowserRead privilege could gain
    UniversalXPConnect privileges and possibly execute code or obtain
    sensitive data.  [MFSA-2006-53]
    Multiple vulnerabilities allow remote attackers to cause a denial
    of service (crash) and possibly execute arbitrary code.
    [MFSA-2006-55]
For the stable distribution (sarge) these problems have been fixed in
version 1.0.4-2sarge11.
For the unstable distribution (sid) these problems have been fixed in
version 1.5.dfsg+1.5.0.5-1.
We recommend that you upgrade your mozilla-firefox package.


Solution : http://www.debian.org/security/2006/dsa-1161
Risk factor : High';

if (description) {
 script_id(22703);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1161");
 script_cve_id("CVE-2006-3805", "CVE-2006-3806", "CVE-2006-3807", "CVE-2006-3808", "CVE-2006-3809", "CVE-2006-3811");
 script_bugtraq_id(19181);
 script_xref(name: "CERT", value: "655892");
 script_xref(name: "CERT", value: "687396");
 script_xref(name: "CERT", value: "876420");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1161] DSA-1161-2 mozilla-firefox");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1161-2 mozilla-firefox");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mozilla-firefox', release: '', reference: '1.5.dfsg+1.5.0.5-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox is vulnerable in Debian .\nUpgrade to mozilla-firefox_1.5.dfsg+1.5.0.5-1\n');
}
if (deb_check(prefix: 'mozilla-firefox', release: '3.1', reference: '1.0.4-2sarge11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox is vulnerable in Debian 3.1.\nUpgrade to mozilla-firefox_1.0.4-2sarge11\n');
}
if (deb_check(prefix: 'mozilla-firefox-dom-inspector', release: '3.1', reference: '1.0.4-2sarge11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox-dom-inspector is vulnerable in Debian 3.1.\nUpgrade to mozilla-firefox-dom-inspector_1.0.4-2sarge11\n');
}
if (deb_check(prefix: 'mozilla-firefox-gnome-support', release: '3.1', reference: '1.0.4-2sarge11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox-gnome-support is vulnerable in Debian 3.1.\nUpgrade to mozilla-firefox-gnome-support_1.0.4-2sarge11\n');
}
if (deb_check(prefix: 'mozilla-firefox', release: '3.1', reference: '1.0.4-2sarge11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox is vulnerable in Debian sarge.\nUpgrade to mozilla-firefox_1.0.4-2sarge11\n');
}
if (w) { security_hole(port: 0, data: desc); }
