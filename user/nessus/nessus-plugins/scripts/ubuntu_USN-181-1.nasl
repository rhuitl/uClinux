# This script was automatically generated from the 181-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libnspr-dev 
- libnspr4 
- libnss-dev 
- libnss3 
- mozilla 
- mozilla-browser 
- mozilla-calendar 
- mozilla-chatzilla 
- mozilla-dev 
- mozilla-dom-inspector 
- mozilla-firefox 
- mozilla-firefox-dev 
- mozilla-firefox-dom-inspector 
- mozilla-firefox-gnome-support 
- mozilla-js-debugger 
- mozilla-mailnews 
- mozilla-psm 
- mozilla-thunderbird 
- mozilla-thunderbird-dev 
- mozilla-thunderbird-inspector 
- mozilla-thunderbird-offline 
- mozilla-thund
[...]

Description :

Tom Ferris discovered a buffer overflow in the Mozilla products
(Mozilla browser, Firefox, Thunderbird). By tricking an user to click
on a Hyperlink with a specially crafted destination URL, a remote
attacker could crash the application. It might even be possible to
exploit this vulnerability to execute arbitrary code, but this has
not yet been confirmed.

Solution :

Upgrade to : 
- libnspr-dev-1.7.10-0ubuntu05.04.1 (Ubuntu 4.10)
- libnspr4-1.7.10-0ubuntu05.04.1 (Ubuntu 4.10)
- libnss-dev-1.7.10-0ubuntu05.04.1 (Ubuntu 4.10)
- libnss3-1.7.10-0ubuntu05.04.1 (Ubuntu 4.10)
- mozilla-1.7.10-0ubuntu05.04.1 (Ubuntu 4.10)
- mozilla-browser-1.7.10-0ubuntu05.04.1 (Ubuntu 4.10)
- mozilla-calendar-1.7.10-0ubuntu05.04.1 (Ubuntu 4.10)
- mozilla-chatzilla-1.7.10-0ubuntu05.04.1 (Ubuntu 4.10)
- mozilla-dev-1.7.10-0ubuntu05.04.1 (Ubuntu 4.10)
- mozilla-dom-inspector-1.7.10-0ubuntu05.04.
[...]


Risk factor : High
';

if (description) {
script_id(20592);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "181-1");
script_summary(english:"mozilla, mozilla-thunderbird, mozilla-firefox vulnerabilities");
script_name(english:"USN181-1 : mozilla, mozilla-thunderbird, mozilla-firefox vulnerabilities");
script_cve_id("CVE-2005-2871");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "libnspr-dev", pkgver: "1.7.10-0ubuntu05.04.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libnspr-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libnspr-dev-1.7.10-0ubuntu05.04.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libnspr4", pkgver: "1.7.10-0ubuntu05.04.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libnspr4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libnspr4-1.7.10-0ubuntu05.04.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libnss-dev", pkgver: "1.7.10-0ubuntu05.04.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libnss-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libnss-dev-1.7.10-0ubuntu05.04.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libnss3", pkgver: "1.7.10-0ubuntu05.04.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libnss3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libnss3-1.7.10-0ubuntu05.04.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla", pkgver: "1.7.10-0ubuntu05.04.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-1.7.10-0ubuntu05.04.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-browser", pkgver: "1.7.10-0ubuntu05.04.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-browser-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-browser-1.7.10-0ubuntu05.04.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-calendar", pkgver: "1.7.10-0ubuntu05.04.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-calendar-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-calendar-1.7.10-0ubuntu05.04.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-chatzilla", pkgver: "1.7.10-0ubuntu05.04.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-chatzilla-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-chatzilla-1.7.10-0ubuntu05.04.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-dev", pkgver: "1.7.10-0ubuntu05.04.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-dev-1.7.10-0ubuntu05.04.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-dom-inspector", pkgver: "1.7.10-0ubuntu05.04.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-dom-inspector-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-dom-inspector-1.7.10-0ubuntu05.04.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-firefox", pkgver: "1.0.6-0ubuntu0.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-firefox-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-firefox-1.0.6-0ubuntu0.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-firefox-dev", pkgver: "1.0.6-0ubuntu0.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-firefox-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-firefox-dev-1.0.6-0ubuntu0.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-firefox-dom-inspector", pkgver: "1.0.6-0ubuntu0.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-firefox-dom-inspector-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-firefox-dom-inspector-1.0.6-0ubuntu0.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-firefox-gnome-support", pkgver: "1.0.6-0ubuntu0.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-firefox-gnome-support-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-firefox-gnome-support-1.0.6-0ubuntu0.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-js-debugger", pkgver: "1.7.10-0ubuntu05.04.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-js-debugger-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-js-debugger-1.7.10-0ubuntu05.04.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-mailnews", pkgver: "1.7.10-0ubuntu05.04.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-mailnews-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-mailnews-1.7.10-0ubuntu05.04.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-psm", pkgver: "1.7.10-0ubuntu05.04.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-psm-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-psm-1.7.10-0ubuntu05.04.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-thunderbird", pkgver: "1.0.6-0ubuntu05.04.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-thunderbird-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-thunderbird-1.0.6-0ubuntu05.04.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-thunderbird-dev", pkgver: "1.0.6-0ubuntu05.04.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-thunderbird-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-thunderbird-dev-1.0.6-0ubuntu05.04.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-thunderbird-inspector", pkgver: "1.0.6-0ubuntu05.04.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-thunderbird-inspector-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-thunderbird-inspector-1.0.6-0ubuntu05.04.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-thunderbird-offline", pkgver: "1.0.6-0ubuntu05.04.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-thunderbird-offline-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-thunderbird-offline-1.0.6-0ubuntu05.04.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-thunderbird-typeaheadfind", pkgver: "1.0.6-0ubuntu05.04.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-thunderbird-typeaheadfind-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-thunderbird-typeaheadfind-1.0.6-0ubuntu05.04.1
');
}

if (w) { security_hole(port: 0, data: desc); }
