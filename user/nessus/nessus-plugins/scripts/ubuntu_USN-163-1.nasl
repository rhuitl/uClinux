# This script was automatically generated from the 163-1 Ubuntu Security Notice
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
- xpdf 
- xpdf-common 
- xpdf-reader 
- xpdf-utils 


Description :

xpdf and kpdf did not sufficiently verify the validity of the "loca"
table in PDF files, a table that contains glyph description
information for embedded TrueType fonts. After detecting the broken
table, xpdf attempted to reconstruct the information in it, which
caused the generation of a huge temporary file that quickly filled up
available disk space and rendered the application unresponsive.

The CUPS printing system in Ubuntu 5.04 uses the xpdf-utils package to
convert PDF files to PostScript. By attempting to print such a crafted
PDF file, a remote attacker could cause a Denial of Service in a print
server. The CUPS system in Ubuntu 4.10 is not vulnerable against this
attack.

Solution :

Upgrade to : 
- kamera-3.4.0-0ubuntu3.1 (Ubuntu 5.04)
- kcoloredit-3.4.0-0ubuntu3.1 (Ubuntu 5.04)
- kdegraphics-3.4.0-0ubuntu3.1 (Ubuntu 5.04)
- kdegraphics-dev-3.4.0-0ubuntu3.1 (Ubuntu 5.04)
- kdegraphics-kfile-plugins-3.4.0-0ubuntu3.1 (Ubuntu 5.04)
- kdvi-3.4.0-0ubuntu3.1 (Ubuntu 5.04)
- kfax-3.4.0-0ubuntu3.1 (Ubuntu 5.04)
- kgamma-3.4.0-0ubuntu3.1 (Ubuntu 5.04)
- kghostview-3.4.0-0ubuntu3.1 (Ubuntu 5.04)
- kiconedit-3.4.0-0ubuntu3.1 (Ubuntu 5.04)
- kmrml-3.4.0-0ubuntu3.1 (Ubuntu 5.04)
- kolourpaint-3.4.
[...]


Risk factor : High
';

if (description) {
script_id(20569);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "163-1");
script_summary(english:"xpdf vulnerability");
script_name(english:"USN163-1 : xpdf vulnerability");
script_cve_id("CVE-2005-2097");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "kamera", pkgver: "3.4.0-0ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kamera-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kamera-3.4.0-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kcoloredit", pkgver: "3.4.0-0ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kcoloredit-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kcoloredit-3.4.0-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kdegraphics", pkgver: "3.4.0-0ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdegraphics-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdegraphics-3.4.0-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kdegraphics-dev", pkgver: "3.4.0-0ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdegraphics-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdegraphics-dev-3.4.0-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kdegraphics-kfile-plugins", pkgver: "3.4.0-0ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdegraphics-kfile-plugins-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdegraphics-kfile-plugins-3.4.0-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kdvi", pkgver: "3.4.0-0ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdvi-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdvi-3.4.0-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kfax", pkgver: "3.4.0-0ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kfax-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kfax-3.4.0-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kgamma", pkgver: "3.4.0-0ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kgamma-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kgamma-3.4.0-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kghostview", pkgver: "3.4.0-0ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kghostview-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kghostview-3.4.0-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kiconedit", pkgver: "3.4.0-0ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kiconedit-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kiconedit-3.4.0-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kmrml", pkgver: "3.4.0-0ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kmrml-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kmrml-3.4.0-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kolourpaint", pkgver: "3.4.0-0ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kolourpaint-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kolourpaint-3.4.0-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kooka", pkgver: "3.4.0-0ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kooka-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kooka-3.4.0-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kpdf", pkgver: "3.4.0-0ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kpdf-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kpdf-3.4.0-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kpovmodeler", pkgver: "3.4.0-0ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kpovmodeler-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kpovmodeler-3.4.0-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kruler", pkgver: "3.4.0-0ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kruler-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kruler-3.4.0-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "ksnapshot", pkgver: "3.4.0-0ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package ksnapshot-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to ksnapshot-3.4.0-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "ksvg", pkgver: "3.4.0-0ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package ksvg-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to ksvg-3.4.0-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kuickshow", pkgver: "3.4.0-0ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kuickshow-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kuickshow-3.4.0-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kview", pkgver: "3.4.0-0ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kview-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kview-3.4.0-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kviewshell", pkgver: "3.4.0-0ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kviewshell-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kviewshell-3.4.0-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libkscan-dev", pkgver: "3.4.0-0ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libkscan-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libkscan-dev-3.4.0-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libkscan1", pkgver: "3.4.0-0ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libkscan1-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libkscan1-3.4.0-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "xpdf", pkgver: "3.00-8ubuntu1.5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xpdf-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to xpdf-3.00-8ubuntu1.5
');
}
found = ubuntu_check(osver: "5.04", pkgname: "xpdf-common", pkgver: "3.00-8ubuntu1.5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xpdf-common-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to xpdf-common-3.00-8ubuntu1.5
');
}
found = ubuntu_check(osver: "5.04", pkgname: "xpdf-reader", pkgver: "3.00-8ubuntu1.5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xpdf-reader-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to xpdf-reader-3.00-8ubuntu1.5
');
}
found = ubuntu_check(osver: "5.04", pkgname: "xpdf-utils", pkgver: "3.00-8ubuntu1.5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xpdf-utils-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to xpdf-utils-3.00-8ubuntu1.5
');
}

if (w) { security_hole(port: 0, data: desc); }
