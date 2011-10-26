# This script was automatically generated from the 275-1 Ubuntu Security Notice
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
- mozilla-js-debugger 
- mozilla-mailnews 
- mozilla-psm 


Description :

Web pages with extremely long titles caused subsequent launches of
Mozilla browser to hang for up to a few minutes, or caused Mozilla to
crash on computers with	insufficient memory. (CVE-2005-4134)

Igor Bukanov discovered that the JavaScript engine did not properly
declare some temporary variables. Under some rare circumstances, a
malicious website could exploit this to execute arbitrary code with
the privileges of the user. (CVE-2006-0292, CVE-2006-1742)

The function XULDocument.persist() did not sufficiently validate the
names of attributes. An attacker could exploit this to inject
arbitrary XML code into the file \'localstore.rdf\', which is read and
evaluated at startup. This could include JavaScript commands that
would be run with the user\'s privileges. (CVE-2006-0296)

Due to a flaw in the HTML tag parser a specific sequence of HTML tags
caused memory corruption. A malicious web site could exploit this to
crash the browser or even execute arbitrary code with the user\'s
privileges. (CVE-2006-0748)


[...]

Solution :

Upgrade to : 
- libnspr-dev-1.7.13-0ubuntu5.10 (Ubuntu 5.10)
- libnspr4-1.7.13-0ubuntu5.10 (Ubuntu 5.10)
- libnss-dev-1.7.13-0ubuntu5.10 (Ubuntu 5.10)
- libnss3-1.7.13-0ubuntu5.10 (Ubuntu 5.10)
- mozilla-1.7.13-0ubuntu5.10 (Ubuntu 5.10)
- mozilla-browser-1.7.13-0ubuntu5.10 (Ubuntu 5.10)
- mozilla-calendar-1.7.13-0ubuntu5.10 (Ubuntu 5.10)
- mozilla-chatzilla-1.7.13-0ubuntu5.10 (Ubuntu 5.10)
- mozilla-dev-1.7.13-0ubuntu5.10 (Ubuntu 5.10)
- mozilla-dom-inspector-1.7.13-0ubuntu5.10 (Ubuntu 5.10)
- mozilla-js-d
[...]


Risk factor : High
';

if (description) {
script_id(21301);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "275-1");
script_summary(english:"mozilla vulnerabilities");
script_name(english:"USN275-1 : mozilla vulnerabilities");
script_cve_id("CVE-2005-4134","CVE-2006-0292","CVE-2006-0296","CVE-2006-0748","CVE-2006-0749","CVE-2006-1727","CVE-2006-1728","CVE-2006-1729","CVE-2006-1730","CVE-2006-1731","CVE-2006-1732","CVE-2006-1733","CVE-2006-1734","CVE-2006-1735","CVE-2006-1736","CVE-2006-1737");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "libnspr-dev", pkgver: "1.7.13-0ubuntu5.10");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libnspr-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnspr-dev-1.7.13-0ubuntu5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libnspr4", pkgver: "1.7.13-0ubuntu5.10");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libnspr4-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnspr4-1.7.13-0ubuntu5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libnss-dev", pkgver: "1.7.13-0ubuntu5.10");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libnss-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnss-dev-1.7.13-0ubuntu5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libnss3", pkgver: "1.7.13-0ubuntu5.10");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libnss3-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnss3-1.7.13-0ubuntu5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla", pkgver: "1.7.13-0ubuntu5.10");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-1.7.13-0ubuntu5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-browser", pkgver: "1.7.13-0ubuntu5.10");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-browser-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-browser-1.7.13-0ubuntu5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-calendar", pkgver: "1.7.13-0ubuntu5.10");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-calendar-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-calendar-1.7.13-0ubuntu5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-chatzilla", pkgver: "1.7.13-0ubuntu5.10");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-chatzilla-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-chatzilla-1.7.13-0ubuntu5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-dev", pkgver: "1.7.13-0ubuntu5.10");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-dev-1.7.13-0ubuntu5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-dom-inspector", pkgver: "1.7.13-0ubuntu5.10");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-dom-inspector-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-dom-inspector-1.7.13-0ubuntu5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-js-debugger", pkgver: "1.7.13-0ubuntu5.10");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-js-debugger-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-js-debugger-1.7.13-0ubuntu5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-mailnews", pkgver: "1.7.13-0ubuntu5.10");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-mailnews-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-mailnews-1.7.13-0ubuntu5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-psm", pkgver: "1.7.13-0ubuntu5.10");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-psm-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-psm-1.7.13-0ubuntu5.10
');
}

if (w) { security_hole(port: 0, data: desc); }
