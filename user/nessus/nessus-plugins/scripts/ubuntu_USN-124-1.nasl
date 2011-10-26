# This script was automatically generated from the 124-1 Ubuntu Security Notice
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


Description :

When a popup is blocked the user is given the ability to open that
popup through the popup-blocking status bar icon and, in Firefox,
through the information bar.  Doron Rosenberg noticed that popups
which are permitted by the user were executed with elevated
privileges, which could be abused to automatically install and execute
arbitrary code with the privileges of the user.  (CVE-2005-1153)

It was discovered that the browser did not start with a clean global
JavaScript state for each new website.  This allowed a malicious web
page to define a global variable known to be used by a different site,
allowing malicious code to be executed in the context of that site
(for example, sending web mail or automatic purchasing).
(CVE-2005-1154)

Michael Krax discovered a flaw in the "favicon" links handler.  A
malicious web page could define a favicon link tag as JavaScript,
which could be exploited to execute arbitrary code with the privileges
of the user.  (CVE-2005-1155)

Michael Krax found two flaws in the Search 
[...]

Solution :

Upgrade to : 
- libnspr-dev-1.7.6-1ubuntu2.1 (Ubuntu 5.04)
- libnspr4-1.7.6-1ubuntu2.1 (Ubuntu 5.04)
- libnss-dev-1.7.6-1ubuntu2.1 (Ubuntu 5.04)
- libnss3-1.7.6-1ubuntu2.1 (Ubuntu 5.04)
- mozilla-1.7.6-1ubuntu2.1 (Ubuntu 5.04)
- mozilla-browser-1.7.6-1ubuntu2.1 (Ubuntu 5.04)
- mozilla-calendar-1.7.6-1ubuntu2.1 (Ubuntu 5.04)
- mozilla-chatzilla-1.7.6-1ubuntu2.1 (Ubuntu 5.04)
- mozilla-dev-1.7.6-1ubuntu2.1 (Ubuntu 5.04)
- mozilla-dom-inspector-1.7.6-1ubuntu2.1 (Ubuntu 5.04)
- mozilla-firefox-1.0.2-0ubuntu5.1
[...]


Risk factor : High
';

if (description) {
script_id(20513);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "124-1");
script_summary(english:"mozilla-firefox, mozilla vulnerabilities");
script_name(english:"USN124-1 : mozilla-firefox, mozilla vulnerabilities");
script_cve_id("CVE-2005-1153","CVE-2005-1154","CVE-2005-1155","CVE-2005-1156","CVE-2005-1157","CVE-2005-1158","CVE-2005-1159","CVE-2005-1160");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "libnspr-dev", pkgver: "1.7.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libnspr-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libnspr-dev-1.7.6-1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libnspr4", pkgver: "1.7.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libnspr4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libnspr4-1.7.6-1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libnss-dev", pkgver: "1.7.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libnss-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libnss-dev-1.7.6-1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libnss3", pkgver: "1.7.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libnss3-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libnss3-1.7.6-1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla", pkgver: "1.7.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-1.7.6-1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-browser", pkgver: "1.7.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-browser-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-browser-1.7.6-1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-calendar", pkgver: "1.7.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-calendar-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-calendar-1.7.6-1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-chatzilla", pkgver: "1.7.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-chatzilla-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-chatzilla-1.7.6-1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-dev", pkgver: "1.7.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-dev-1.7.6-1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-dom-inspector", pkgver: "1.7.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-dom-inspector-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-dom-inspector-1.7.6-1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-firefox", pkgver: "1.0.2-0ubuntu5.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-firefox-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-firefox-1.0.2-0ubuntu5.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-firefox-dev", pkgver: "1.0.2-0ubuntu5.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-firefox-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-firefox-dev-1.0.2-0ubuntu5.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-firefox-dom-inspector", pkgver: "1.0.2-0ubuntu5.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-firefox-dom-inspector-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-firefox-dom-inspector-1.0.2-0ubuntu5.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-firefox-gnome-support", pkgver: "1.0.2-0ubuntu5.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-firefox-gnome-support-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-firefox-gnome-support-1.0.2-0ubuntu5.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-js-debugger", pkgver: "1.7.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-js-debugger-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-js-debugger-1.7.6-1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-mailnews", pkgver: "1.7.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-mailnews-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-mailnews-1.7.6-1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-psm", pkgver: "1.7.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-psm-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-psm-1.7.6-1ubuntu2.1
');
}

if (w) { security_hole(port: 0, data: desc); }
