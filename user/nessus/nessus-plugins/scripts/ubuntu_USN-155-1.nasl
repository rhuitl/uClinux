# This script was automatically generated from the 155-1 Ubuntu Security Notice
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

Secunia.com reported that one of the recent security patches in
Firefox reintroduced the frame injection patch that was originally
known as CVE-2004-0718. This allowed a malicious web site to spoof the
contents of other web sites. (CVE-2005-1937)

It was discovered that a malicious website could inject arbitrary
scripts into a target site by loading it into a frame and navigating
back to a previous Javascript URL that contained an eval() call. This
could be used to steal cookies or other confidential data from the
target site. (MFSA 2005-42)

Michael Krax, Georgi Guninski, and L. David Baron found that the
security checks that prevent script injection could be bypassed by
wrapping a javascript: url in another pseudo-protocol like
"view-source:" or "jar:". (CVE-2005-1531)

A variant of the attack described in CVE-2005-1160 (see USN-124-1) was
discovered. Additional checks were added to make sure Javascript eval
and script objects are run with the privileges of the context that
created them, not the potentiall
[...]

Solution :

Upgrade to : 
- libnspr-dev-1.7.10-0ubuntu05.04 (Ubuntu 5.04)
- libnspr4-1.7.10-0ubuntu05.04 (Ubuntu 5.04)
- libnss-dev-1.7.10-0ubuntu05.04 (Ubuntu 5.04)
- libnss3-1.7.10-0ubuntu05.04 (Ubuntu 5.04)
- mozilla-1.7.10-0ubuntu05.04 (Ubuntu 5.04)
- mozilla-browser-1.7.10-0ubuntu05.04 (Ubuntu 5.04)
- mozilla-calendar-1.7.10-0ubuntu05.04 (Ubuntu 5.04)
- mozilla-chatzilla-1.7.10-0ubuntu05.04 (Ubuntu 5.04)
- mozilla-dev-1.7.10-0ubuntu05.04 (Ubuntu 5.04)
- mozilla-dom-inspector-1.7.10-0ubuntu05.04 (Ubuntu 5.04)
- mo
[...]


Risk factor : High
';

if (description) {
script_id(20556);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "155-1");
script_summary(english:"mozilla vulnerabilities");
script_name(english:"USN155-1 : mozilla vulnerabilities");
script_cve_id("CVE-2004-0718","CVE-2005-1160","CVE-2005-1531","CVE-2005-1532","CVE-2005-1937","CVE-2005-2260","CVE-2005-2261","CVE-2005-2263","CVE-2005-2265","CVE-2005-2266","CVE-2005-2268","CVE-2005-2269","CVE-2005-2270");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "libnspr-dev", pkgver: "1.7.10-0ubuntu05.04");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libnspr-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libnspr-dev-1.7.10-0ubuntu05.04
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libnspr4", pkgver: "1.7.10-0ubuntu05.04");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libnspr4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libnspr4-1.7.10-0ubuntu05.04
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libnss-dev", pkgver: "1.7.10-0ubuntu05.04");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libnss-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libnss-dev-1.7.10-0ubuntu05.04
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libnss3", pkgver: "1.7.10-0ubuntu05.04");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libnss3-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libnss3-1.7.10-0ubuntu05.04
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla", pkgver: "1.7.10-0ubuntu05.04");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-1.7.10-0ubuntu05.04
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-browser", pkgver: "1.7.10-0ubuntu05.04");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-browser-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-browser-1.7.10-0ubuntu05.04
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-calendar", pkgver: "1.7.10-0ubuntu05.04");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-calendar-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-calendar-1.7.10-0ubuntu05.04
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-chatzilla", pkgver: "1.7.10-0ubuntu05.04");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-chatzilla-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-chatzilla-1.7.10-0ubuntu05.04
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-dev", pkgver: "1.7.10-0ubuntu05.04");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-dev-1.7.10-0ubuntu05.04
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-dom-inspector", pkgver: "1.7.10-0ubuntu05.04");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-dom-inspector-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-dom-inspector-1.7.10-0ubuntu05.04
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-js-debugger", pkgver: "1.7.10-0ubuntu05.04");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-js-debugger-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-js-debugger-1.7.10-0ubuntu05.04
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-mailnews", pkgver: "1.7.10-0ubuntu05.04");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-mailnews-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-mailnews-1.7.10-0ubuntu05.04
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-psm", pkgver: "1.7.10-0ubuntu05.04");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-psm-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-psm-1.7.10-0ubuntu05.04
');
}

if (w) { security_hole(port: 0, data: desc); }
