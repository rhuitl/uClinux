# This script was automatically generated from the 202-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- karbon 
- kchart 
- kformula 
- kivio 
- kivio-data 
- koffice 
- koffice-data 
- koffice-dev 
- koffice-doc-html 
- koffice-libs 
- koshell 
- kpresenter 
- kspread 
- kugar 
- kword 


Description :

Chris Evans discovered a buffer overflow in the RTF import module of
KOffice. By tricking a user into opening a specially-crafted RTF file,
an attacker could exploit this to execute arbitrary code with the
privileges of the AbiWord user.

Solution :

Upgrade to : 
- karbon-1.3.5-2ubuntu1.1 (Ubuntu 5.04)
- kchart-1.3.5-2ubuntu1.1 (Ubuntu 5.04)
- kformula-1.3.5-2ubuntu1.1 (Ubuntu 5.04)
- kivio-1.3.5-2ubuntu1.1 (Ubuntu 5.04)
- kivio-data-1.3.5-2ubuntu1.1 (Ubuntu 5.04)
- koffice-1.3.5-2ubuntu1.1 (Ubuntu 5.04)
- koffice-data-1.3.5-2ubuntu1.1 (Ubuntu 5.04)
- koffice-dev-1.3.5-2ubuntu1.1 (Ubuntu 5.04)
- koffice-doc-html-1.3.5-2ubuntu1.1 (Ubuntu 5.04)
- koffice-libs-1.3.5-2ubuntu1.1 (Ubuntu 5.04)
- koshell-1.3.5-2ubuntu1.1 (Ubuntu 5.04)
- kpresenter-1.3.5-2ubu
[...]


Risk factor : High
';

if (description) {
script_id(20618);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "202-1");
script_summary(english:"koffice vulnerability");
script_name(english:"USN202-1 : koffice vulnerability");
script_cve_id("CVE-2005-2971");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "karbon", pkgver: "1.3.5-2ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package karbon-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to karbon-1.3.5-2ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kchart", pkgver: "1.3.5-2ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kchart-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kchart-1.3.5-2ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kformula", pkgver: "1.3.5-2ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kformula-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kformula-1.3.5-2ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kivio", pkgver: "1.3.5-2ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kivio-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kivio-1.3.5-2ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kivio-data", pkgver: "1.3.5-2ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kivio-data-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kivio-data-1.3.5-2ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "koffice", pkgver: "1.3.5-2ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package koffice-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to koffice-1.3.5-2ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "koffice-data", pkgver: "1.3.5-2ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package koffice-data-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to koffice-data-1.3.5-2ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "koffice-dev", pkgver: "1.3.5-2ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package koffice-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to koffice-dev-1.3.5-2ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "koffice-doc-html", pkgver: "1.3.5-2ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package koffice-doc-html-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to koffice-doc-html-1.3.5-2ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "koffice-libs", pkgver: "1.3.5-2ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package koffice-libs-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to koffice-libs-1.3.5-2ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "koshell", pkgver: "1.3.5-2ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package koshell-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to koshell-1.3.5-2ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kpresenter", pkgver: "1.3.5-2ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kpresenter-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kpresenter-1.3.5-2ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kspread", pkgver: "1.3.5-2ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kspread-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kspread-1.3.5-2ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kugar", pkgver: "1.3.5-2ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kugar-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kugar-1.3.5-2ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kword", pkgver: "1.3.5-2ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kword-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kword-1.3.5-2ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
