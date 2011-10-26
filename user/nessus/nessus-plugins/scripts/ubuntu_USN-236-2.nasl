# This script was automatically generated from the 236-2 Ubuntu Security Notice
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
- karbon 
- kchart 
- kcoloredit 
- kdegraphics 
- kdegraphics-dev 
- kdegraphics-doc-html 
- kdegraphics-kfile-plugins 
- kdvi 
- kfax 
- kformula 
- kgamma 
- kghostview 
- kiconedit 
- kivio 
- kivio-data 
- kmrml 
- koffice 
- koffice-data 
- koffice-dev 
- koffice-doc-html 
- koffice-libs 
- kolourpaint 
- kooka 
- koshell 
- kpdf 
- kpovmodeler 
- kpresenter 
- krita 
- kruler 
- ksnapshot 
- kspread 
- ksvg 
- kthesaurus 
- kugar 
- kuic
[...]

Description :

USN-236-1 fixed several vulnerabilities in xpdf. kpdf and kword
contain copies of xpdf code and are thus vulnerable to the same
issues.

For reference, this is the original advisory:

  Chris Evans discovered several integer overflows in the XPDF code,
  which is present in xpdf, the Poppler library, and tetex-bin. By
  tricking an user into opening a specially crafted PDF file, an
  attacker could exploit this to execute arbitrary code with the
  privileges of the application that processes the document.

Solution :

Upgrade to : 
- kamera-3.4.3-0ubuntu2.2 (Ubuntu 5.10)
- karbon-1.4.1-0ubuntu7.2 (Ubuntu 5.10)
- kchart-1.4.1-0ubuntu7.2 (Ubuntu 5.10)
- kcoloredit-3.4.3-0ubuntu2.2 (Ubuntu 5.10)
- kdegraphics-3.4.3-0ubuntu2.2 (Ubuntu 5.10)
- kdegraphics-dev-3.4.3-0ubuntu2.2 (Ubuntu 5.10)
- kdegraphics-doc-html-3.4.3-0ubuntu2.2 (Ubuntu 5.10)
- kdegraphics-kfile-plugins-3.4.3-0ubuntu2.2 (Ubuntu 5.10)
- kdvi-3.4.3-0ubuntu2.2 (Ubuntu 5.10)
- kfax-3.4.3-0ubuntu2.2 (Ubuntu 5.10)
- kformula-1.4.1-0ubuntu7.2 (Ubuntu 5.10)
- kgamma
[...]


Risk factor : High
';

if (description) {
script_id(20782);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "236-2");
script_summary(english:"kdegraphics, koffice vulnerabilities");
script_name(english:"USN236-2 : kdegraphics, koffice vulnerabilities");
script_cve_id("CVE-2005-3624","CVE-2005-3625","CVE-2005-3626","CVE-2005-3627");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "kamera", pkgver: "3.4.3-0ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kamera-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kamera-3.4.3-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "karbon", pkgver: "1.4.1-0ubuntu7.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package karbon-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to karbon-1.4.1-0ubuntu7.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kchart", pkgver: "1.4.1-0ubuntu7.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kchart-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kchart-1.4.1-0ubuntu7.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kcoloredit", pkgver: "3.4.3-0ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kcoloredit-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kcoloredit-3.4.3-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kdegraphics", pkgver: "3.4.3-0ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdegraphics-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kdegraphics-3.4.3-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kdegraphics-dev", pkgver: "3.4.3-0ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdegraphics-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kdegraphics-dev-3.4.3-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kdegraphics-doc-html", pkgver: "3.4.3-0ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdegraphics-doc-html-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kdegraphics-doc-html-3.4.3-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kdegraphics-kfile-plugins", pkgver: "3.4.3-0ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdegraphics-kfile-plugins-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kdegraphics-kfile-plugins-3.4.3-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kdvi", pkgver: "3.4.3-0ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdvi-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kdvi-3.4.3-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kfax", pkgver: "3.4.3-0ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kfax-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kfax-3.4.3-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kformula", pkgver: "1.4.1-0ubuntu7.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kformula-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kformula-1.4.1-0ubuntu7.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kgamma", pkgver: "3.4.3-0ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kgamma-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kgamma-3.4.3-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kghostview", pkgver: "3.4.3-0ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kghostview-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kghostview-3.4.3-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kiconedit", pkgver: "3.4.3-0ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kiconedit-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kiconedit-3.4.3-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kivio", pkgver: "1.4.1-0ubuntu7.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kivio-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kivio-1.4.1-0ubuntu7.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kivio-data", pkgver: "1.4.1-0ubuntu7.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kivio-data-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kivio-data-1.4.1-0ubuntu7.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kmrml", pkgver: "3.4.3-0ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kmrml-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kmrml-3.4.3-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "koffice", pkgver: "1.4.1-0ubuntu7.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package koffice-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to koffice-1.4.1-0ubuntu7.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "koffice-data", pkgver: "1.4.1-0ubuntu7.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package koffice-data-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to koffice-data-1.4.1-0ubuntu7.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "koffice-dev", pkgver: "1.4.1-0ubuntu7.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package koffice-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to koffice-dev-1.4.1-0ubuntu7.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "koffice-doc-html", pkgver: "1.4.1-0ubuntu7.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package koffice-doc-html-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to koffice-doc-html-1.4.1-0ubuntu7.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "koffice-libs", pkgver: "1.4.1-0ubuntu7.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package koffice-libs-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to koffice-libs-1.4.1-0ubuntu7.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kolourpaint", pkgver: "3.4.3-0ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kolourpaint-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kolourpaint-3.4.3-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kooka", pkgver: "3.4.3-0ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kooka-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kooka-3.4.3-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "koshell", pkgver: "1.4.1-0ubuntu7.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package koshell-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to koshell-1.4.1-0ubuntu7.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kpdf", pkgver: "3.4.3-0ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kpdf-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kpdf-3.4.3-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kpovmodeler", pkgver: "3.4.3-0ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kpovmodeler-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kpovmodeler-3.4.3-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kpresenter", pkgver: "1.4.1-0ubuntu7.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kpresenter-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kpresenter-1.4.1-0ubuntu7.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "krita", pkgver: "1.4.1-0ubuntu7.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package krita-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to krita-1.4.1-0ubuntu7.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kruler", pkgver: "3.4.3-0ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kruler-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kruler-3.4.3-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "ksnapshot", pkgver: "3.4.3-0ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package ksnapshot-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to ksnapshot-3.4.3-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kspread", pkgver: "1.4.1-0ubuntu7.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kspread-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kspread-1.4.1-0ubuntu7.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "ksvg", pkgver: "3.4.3-0ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package ksvg-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to ksvg-3.4.3-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kthesaurus", pkgver: "1.4.1-0ubuntu7.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kthesaurus-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kthesaurus-1.4.1-0ubuntu7.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kugar", pkgver: "1.4.1-0ubuntu7.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kugar-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kugar-1.4.1-0ubuntu7.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kuickshow", pkgver: "3.4.3-0ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kuickshow-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kuickshow-3.4.3-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kview", pkgver: "3.4.3-0ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kview-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kview-3.4.3-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kviewshell", pkgver: "3.4.3-0ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kviewshell-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kviewshell-3.4.3-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kword", pkgver: "1.4.1-0ubuntu7.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kword-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kword-1.4.1-0ubuntu7.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libkscan-dev", pkgver: "3.4.3-0ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libkscan-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libkscan-dev-3.4.3-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libkscan1", pkgver: "3.4.3-0ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libkscan1-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libkscan1-3.4.3-0ubuntu2.2
');
}

if (w) { security_hole(port: 0, data: desc); }
