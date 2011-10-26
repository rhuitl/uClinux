# This script was automatically generated from the 236-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- cupsys 
- cupsys-bsd 
- cupsys-client 
- libcupsimage2 
- libcupsimage2-dev 
- libcupsys2-dev 
- libcupsys2-gnutls10 
- libkpathsea-dev 
- libkpathsea3 
- libpoppler-dev 
- libpoppler-glib-dev 
- libpoppler-qt-dev 
- libpoppler0c2 
- libpoppler0c2-glib 
- libpoppler0c2-qt 
- poppler-utils 
- tetex-bin 
- xpdf 
- xpdf-common 
- xpdf-reader 
- xpdf-utils 


Description :

Chris Evans discovered several integer overflows in the XPDF code,
which is present in xpdf, the Poppler library, and tetex-bin. By
tricking an user into opening a specially crafted PDF file, an
attacker could exploit this to execute arbitrary code with the
privileges of the application that processes the document.

The CUPS printing system also uses XPDF code to convert PDF files to
PostScript. By attempting to print such a crafted PDF file, a remote
attacker could execute arbitrary code with the privileges of the
printer server (user \'cupsys\').

Solution :

Upgrade to : 
- cupsys-1.1.20final+cvs20040330-4ubuntu16.10 (Ubuntu 4.10)
- cupsys-bsd-1.1.20final+cvs20040330-4ubuntu16.10 (Ubuntu 4.10)
- cupsys-client-1.1.20final+cvs20040330-4ubuntu16.10 (Ubuntu 4.10)
- libcupsimage2-1.1.20final+cvs20040330-4ubuntu16.10 (Ubuntu 4.10)
- libcupsimage2-dev-1.1.20final+cvs20040330-4ubuntu16.10 (Ubuntu 4.10)
- libcupsys2-dev-1.1.20final+cvs20040330-4ubuntu16.10 (Ubuntu 4.10)
- libcupsys2-gnutls10-1.1.20final+cvs20040330-4ubuntu16.10 (Ubuntu 4.10)
- libkpathsea-dev-2.0.2-30u
[...]


Risk factor : High
';

if (description) {
script_id(20781);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "236-1");
script_summary(english:"xpdf, poppler, cupsys, tetex-bin vulnerabilities");
script_name(english:"USN236-1 : xpdf, poppler, cupsys, tetex-bin vulnerabilities");
script_cve_id("CVE-2005-3624","CVE-2005-3625","CVE-2005-3626","CVE-2005-3627");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "cupsys", pkgver: "1.1.20final+cvs20040330-4ubuntu16.10");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cupsys-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cupsys-1.1.20final+cvs20040330-4ubuntu16.10
');
}
found = ubuntu_check(osver: "4.10", pkgname: "cupsys-bsd", pkgver: "1.1.20final+cvs20040330-4ubuntu16.10");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cupsys-bsd-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cupsys-bsd-1.1.20final+cvs20040330-4ubuntu16.10
');
}
found = ubuntu_check(osver: "4.10", pkgname: "cupsys-client", pkgver: "1.1.20final+cvs20040330-4ubuntu16.10");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cupsys-client-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cupsys-client-1.1.20final+cvs20040330-4ubuntu16.10
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcupsimage2", pkgver: "1.1.20final+cvs20040330-4ubuntu16.10");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcupsimage2-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcupsimage2-1.1.20final+cvs20040330-4ubuntu16.10
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcupsimage2-dev", pkgver: "1.1.20final+cvs20040330-4ubuntu16.10");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcupsimage2-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcupsimage2-dev-1.1.20final+cvs20040330-4ubuntu16.10
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcupsys2-dev", pkgver: "1.1.20final+cvs20040330-4ubuntu16.10");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcupsys2-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcupsys2-dev-1.1.20final+cvs20040330-4ubuntu16.10
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcupsys2-gnutls10", pkgver: "1.1.20final+cvs20040330-4ubuntu16.10");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcupsys2-gnutls10-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcupsys2-gnutls10-1.1.20final+cvs20040330-4ubuntu16.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libkpathsea-dev", pkgver: "2.0.2-30ubuntu3.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libkpathsea-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libkpathsea-dev-2.0.2-30ubuntu3.4
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libkpathsea3", pkgver: "2.0.2-30ubuntu3.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libkpathsea3-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libkpathsea3-2.0.2-30ubuntu3.4
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libpoppler-dev", pkgver: "0.4.2-0ubuntu6.5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpoppler-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libpoppler-dev-0.4.2-0ubuntu6.5
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libpoppler-glib-dev", pkgver: "0.4.2-0ubuntu6.5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpoppler-glib-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libpoppler-glib-dev-0.4.2-0ubuntu6.5
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libpoppler-qt-dev", pkgver: "0.4.2-0ubuntu6.5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpoppler-qt-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libpoppler-qt-dev-0.4.2-0ubuntu6.5
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libpoppler0c2", pkgver: "0.4.2-0ubuntu6.5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpoppler0c2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libpoppler0c2-0.4.2-0ubuntu6.5
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libpoppler0c2-glib", pkgver: "0.4.2-0ubuntu6.5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpoppler0c2-glib-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libpoppler0c2-glib-0.4.2-0ubuntu6.5
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libpoppler0c2-qt", pkgver: "0.4.2-0ubuntu6.5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpoppler0c2-qt-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libpoppler0c2-qt-0.4.2-0ubuntu6.5
');
}
found = ubuntu_check(osver: "5.10", pkgname: "poppler-utils", pkgver: "0.4.2-0ubuntu6.5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package poppler-utils-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to poppler-utils-0.4.2-0ubuntu6.5
');
}
found = ubuntu_check(osver: "5.10", pkgname: "tetex-bin", pkgver: "2.0.2-30ubuntu3.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package tetex-bin-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to tetex-bin-2.0.2-30ubuntu3.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "xpdf", pkgver: "3.00-11ubuntu3.6");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xpdf-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to xpdf-3.00-11ubuntu3.6
');
}
found = ubuntu_check(osver: "5.04", pkgname: "xpdf-common", pkgver: "3.00-11ubuntu3.6");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xpdf-common-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to xpdf-common-3.00-11ubuntu3.6
');
}
found = ubuntu_check(osver: "5.04", pkgname: "xpdf-reader", pkgver: "3.00-11ubuntu3.6");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xpdf-reader-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to xpdf-reader-3.00-11ubuntu3.6
');
}
found = ubuntu_check(osver: "5.04", pkgname: "xpdf-utils", pkgver: "3.00-11ubuntu3.6");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xpdf-utils-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to xpdf-utils-3.00-11ubuntu3.6
');
}

if (w) { security_hole(port: 0, data: desc); }
