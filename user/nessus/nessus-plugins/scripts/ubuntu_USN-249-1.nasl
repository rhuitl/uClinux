# This script was automatically generated from the 249-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- kamera 
- kcoloredit 
- kdegraphics 
- kdegraphics-dev 
- kdegraphics-doc-html 
- kdegraphics-kfile-plugins 
- kdvi 
- kfax 
- kgamma 
- kghostview 
- kiconedit 
- kmrml 
- kolourpaint 
- kooka 
- kpdf 
- kpovmodeler 
- kruler 
- ksnapshot 
- ksvg 
- kuickshow 
- kview 
- kviewshell 
- libkscan-dev 
- libkscan1 
- libpoppler-dev 
- libpoppler-glib-dev 
- libpoppler-qt-dev 
- libpoppler0c2 
- libpoppler0c2-glib 
- libpoppler0c2-qt 
- poppler-utils 
- xp
[...]

Description :

The splash image handler in xpdf did not check the validity of
coordinates. By tricking a user into opening a specially crafted PDF
file, an attacker could exploit this to trigger a buffer overflow
which could lead to arbitrary code execution with the privileges of
the user.

The poppler library and kpdf also contain xpdf code, and thus are
affected by the same vulnerability.

Solution :

Upgrade to : 
- kamera-3.4.3-0ubuntu2.3 (Ubuntu 5.10)
- kcoloredit-3.4.3-0ubuntu2.3 (Ubuntu 5.10)
- kdegraphics-3.4.3-0ubuntu2.3 (Ubuntu 5.10)
- kdegraphics-dev-3.4.3-0ubuntu2.3 (Ubuntu 5.10)
- kdegraphics-doc-html-3.4.3-0ubuntu2.3 (Ubuntu 5.10)
- kdegraphics-kfile-plugins-3.4.3-0ubuntu2.3 (Ubuntu 5.10)
- kdvi-3.4.3-0ubuntu2.3 (Ubuntu 5.10)
- kfax-3.4.3-0ubuntu2.3 (Ubuntu 5.10)
- kgamma-3.4.3-0ubuntu2.3 (Ubuntu 5.10)
- kghostview-3.4.3-0ubuntu2.3 (Ubuntu 5.10)
- kiconedit-3.4.3-0ubuntu2.3 (Ubuntu 5.10)
- k
[...]


Risk factor : High
';

if (description) {
script_id(21058);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "249-1");
script_summary(english:"xpdf, poppler, kdegraphics vulnerabilities");
script_name(english:"USN249-1 : xpdf, poppler, kdegraphics vulnerabilities");
script_cve_id("CVE-2006-0301");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "kamera", pkgver: "3.4.3-0ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kamera-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kamera-3.4.3-0ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kcoloredit", pkgver: "3.4.3-0ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kcoloredit-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kcoloredit-3.4.3-0ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kdegraphics", pkgver: "3.4.3-0ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdegraphics-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kdegraphics-3.4.3-0ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kdegraphics-dev", pkgver: "3.4.3-0ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdegraphics-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kdegraphics-dev-3.4.3-0ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kdegraphics-doc-html", pkgver: "3.4.3-0ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdegraphics-doc-html-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kdegraphics-doc-html-3.4.3-0ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kdegraphics-kfile-plugins", pkgver: "3.4.3-0ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdegraphics-kfile-plugins-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kdegraphics-kfile-plugins-3.4.3-0ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kdvi", pkgver: "3.4.3-0ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdvi-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kdvi-3.4.3-0ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kfax", pkgver: "3.4.3-0ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kfax-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kfax-3.4.3-0ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kgamma", pkgver: "3.4.3-0ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kgamma-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kgamma-3.4.3-0ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kghostview", pkgver: "3.4.3-0ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kghostview-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kghostview-3.4.3-0ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kiconedit", pkgver: "3.4.3-0ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kiconedit-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kiconedit-3.4.3-0ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kmrml", pkgver: "3.4.3-0ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kmrml-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kmrml-3.4.3-0ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kolourpaint", pkgver: "3.4.3-0ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kolourpaint-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kolourpaint-3.4.3-0ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kooka", pkgver: "3.4.3-0ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kooka-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kooka-3.4.3-0ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kpdf", pkgver: "3.4.3-0ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kpdf-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kpdf-3.4.3-0ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kpovmodeler", pkgver: "3.4.3-0ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kpovmodeler-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kpovmodeler-3.4.3-0ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kruler", pkgver: "3.4.3-0ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kruler-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kruler-3.4.3-0ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "ksnapshot", pkgver: "3.4.3-0ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package ksnapshot-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to ksnapshot-3.4.3-0ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "ksvg", pkgver: "3.4.3-0ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package ksvg-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to ksvg-3.4.3-0ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kuickshow", pkgver: "3.4.3-0ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kuickshow-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kuickshow-3.4.3-0ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kview", pkgver: "3.4.3-0ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kview-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kview-3.4.3-0ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kviewshell", pkgver: "3.4.3-0ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kviewshell-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kviewshell-3.4.3-0ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libkscan-dev", pkgver: "3.4.3-0ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libkscan-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libkscan-dev-3.4.3-0ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libkscan1", pkgver: "3.4.3-0ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libkscan1-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libkscan1-3.4.3-0ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libpoppler-dev", pkgver: "0.4.2-0ubuntu6.6");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpoppler-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libpoppler-dev-0.4.2-0ubuntu6.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libpoppler-glib-dev", pkgver: "0.4.2-0ubuntu6.6");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpoppler-glib-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libpoppler-glib-dev-0.4.2-0ubuntu6.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libpoppler-qt-dev", pkgver: "0.4.2-0ubuntu6.6");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpoppler-qt-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libpoppler-qt-dev-0.4.2-0ubuntu6.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libpoppler0c2", pkgver: "0.4.2-0ubuntu6.6");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpoppler0c2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libpoppler0c2-0.4.2-0ubuntu6.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libpoppler0c2-glib", pkgver: "0.4.2-0ubuntu6.6");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpoppler0c2-glib-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libpoppler0c2-glib-0.4.2-0ubuntu6.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libpoppler0c2-qt", pkgver: "0.4.2-0ubuntu6.6");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpoppler0c2-qt-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libpoppler0c2-qt-0.4.2-0ubuntu6.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "poppler-utils", pkgver: "0.4.2-0ubuntu6.6");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package poppler-utils-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to poppler-utils-0.4.2-0ubuntu6.6
');
}
found = ubuntu_check(osver: "5.04", pkgname: "xpdf", pkgver: "3.00-11ubuntu3.7");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xpdf-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to xpdf-3.00-11ubuntu3.7
');
}
found = ubuntu_check(osver: "5.04", pkgname: "xpdf-common", pkgver: "3.00-11ubuntu3.7");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xpdf-common-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to xpdf-common-3.00-11ubuntu3.7
');
}
found = ubuntu_check(osver: "5.04", pkgname: "xpdf-reader", pkgver: "3.00-11ubuntu3.7");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xpdf-reader-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to xpdf-reader-3.00-11ubuntu3.7
');
}
found = ubuntu_check(osver: "5.04", pkgname: "xpdf-utils", pkgver: "3.00-11ubuntu3.7");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xpdf-utils-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to xpdf-utils-3.00-11ubuntu3.7
');
}

if (w) { security_hole(port: 0, data: desc); }
