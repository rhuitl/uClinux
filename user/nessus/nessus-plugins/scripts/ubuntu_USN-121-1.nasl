# This script was automatically generated from the 121-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- openoffice.org 
- openoffice.org-bin 
- openoffice.org-crashrep 
- openoffice.org-gtk-gnome 
- openoffice.org-kde 
- openoffice.org-l10n-af 
- openoffice.org-l10n-ar 
- openoffice.org-l10n-ca 
- openoffice.org-l10n-cs 
- openoffice.org-l10n-cy 
- openoffice.org-l10n-da 
- openoffice.org-l10n-de 
- openoffice.org-l10n-el 
- openoffice.org-l10n-en 
- openoffice.org-l10n-es 
- openoffice.org-l10n-et 
- openoffice.org-l10n-eu 
- openoffice.org-l10n-fi 
- o
[...]

Description :

The StgCompObjStream::Load() failed to check the validity of a length
field in documents. If an attacker tricked a user to open a specially
crafted OpenOffice file, this triggered a buffer overflow which could
lead to arbitrary code execution with the privileges of the user
opening the document.

The update for Ubuntu 5.04 (Hoary Hedgehog) also contains a
translation update: The "openoffice.org-l10n-xh" package now contains
actual Xhosa translations (the previous version just shipped English
strings).

Solution :

Upgrade to : 
- openoffice.org-1.1.3-8ubuntu2.3 (Ubuntu 5.04)
- openoffice.org-bin-1.1.3-8ubuntu2.3 (Ubuntu 5.04)
- openoffice.org-crashrep-1.1.2-2ubuntu6.1 (Ubuntu 4.10)
- openoffice.org-gtk-gnome-1.1.3-8ubuntu2.3 (Ubuntu 5.04)
- openoffice.org-kde-1.1.3-8ubuntu2.3 (Ubuntu 5.04)
- openoffice.org-l10n-af-1.1.3-8ubuntu2.3 (Ubuntu 5.04)
- openoffice.org-l10n-ar-1.1.3-8ubuntu2.3 (Ubuntu 5.04)
- openoffice.org-l10n-ca-1.1.3-8ubuntu2.3 (Ubuntu 5.04)
- openoffice.org-l10n-cs-1.1.3-8ubuntu2.3 (Ubuntu 5.04)
- open
[...]


Risk factor : High
';

if (description) {
script_id(20510);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "121-1");
script_summary(english:"openoffice.org vulnerability");
script_name(english:"USN121-1 : openoffice.org vulnerability");
script_cve_id("CVE-2005-0941");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-bin", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-bin-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-bin-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "openoffice.org-crashrep", pkgver: "1.1.2-2ubuntu6.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-crashrep-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to openoffice.org-crashrep-1.1.2-2ubuntu6.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-gtk-gnome", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-gtk-gnome-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-gtk-gnome-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-kde", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-kde-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-kde-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-af", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-af-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-af-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-ar", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-ar-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-ar-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-ca", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-ca-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-ca-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-cs", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-cs-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-cs-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-cy", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-cy-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-cy-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-da", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-da-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-da-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-de", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-de-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-de-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-el", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-el-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-el-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-en", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-en-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-en-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-es", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-es-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-es-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-et", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-et-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-et-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-eu", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-eu-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-eu-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-fi", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-fi-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-fi-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-fr", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-fr-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-fr-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-gl", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-gl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-gl-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-he", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-he-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-he-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-hi", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-hi-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-hi-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-hu", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-hu-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-hu-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-it", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-it-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-it-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-ja", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-ja-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-ja-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-kn", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-kn-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-kn-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-ko", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-ko-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-ko-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-lt", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-lt-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-lt-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-nb", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-nb-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-nb-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-nl", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-nl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-nl-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-nn", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-nn-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-nn-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-ns", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-ns-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-ns-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-pl", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-pl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-pl-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-pt", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-pt-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-pt-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-pt-br", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-pt-br-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-pt-br-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-ru", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-ru-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-ru-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-sk", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-sk-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-sk-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-sl", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-sl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-sl-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-sv", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-sv-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-sv-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-th", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-th-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-th-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-tr", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-tr-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-tr-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-xh", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-xh-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-xh-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-zh-cn", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-zh-cn-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-zh-cn-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-zh-tw", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-zh-tw-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-zh-tw-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-l10n-zu", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-l10n-zu-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-l10n-zu-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "openoffice.org-mimelnk", pkgver: "1.1.2-2ubuntu6.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-mimelnk-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to openoffice.org-mimelnk-1.1.2-2ubuntu6.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openoffice.org-thesaurus-en-us", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openoffice.org-thesaurus-en-us-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openoffice.org-thesaurus-en-us-1.1.3-8ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "ttf-opensymbol", pkgver: "1.1.3-8ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package ttf-opensymbol-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to ttf-opensymbol-1.1.3-8ubuntu2.3
');
}

if (w) { security_hole(port: 0, data: desc); }
