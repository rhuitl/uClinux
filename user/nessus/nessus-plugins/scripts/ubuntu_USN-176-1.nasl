# This script was automatically generated from the 176-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- kappfinder 
- kate 
- kcontrol 
- kdebase 
- kdebase-bin 
- kdebase-data 
- kdebase-dev 
- kdebase-doc 
- kdebase-kio-plugins 
- kdepasswd 
- kdeprint 
- kdesktop 
- kdm 
- kfind 
- khelpcenter 
- kicker 
- klipper 
- kmenuedit 
- konqueror 
- konqueror-nsplugins 
- konsole 
- kpager 
- kpersonalizer 
- ksmserver 
- ksplash 
- ksysguard 
- ksysguardd 
- ktip 
- kwin 
- libkonq4 
- libkonq4-dev 
- xfonts-konsole 


Description :

Ilja van Sprundel discovered a flaw in the lock file handling of
kcheckpass. A local attacker could exploit this to execute arbitrary
code with root privileges.

Solution :

Upgrade to : 
- kappfinder-3.4.0-0ubuntu18.1 (Ubuntu 5.04)
- kate-3.4.0-0ubuntu18.1 (Ubuntu 5.04)
- kcontrol-3.4.0-0ubuntu18.1 (Ubuntu 5.04)
- kdebase-3.4.0-0ubuntu18.1 (Ubuntu 5.04)
- kdebase-bin-3.4.0-0ubuntu18.1 (Ubuntu 5.04)
- kdebase-data-3.4.0-0ubuntu18.1 (Ubuntu 5.04)
- kdebase-dev-3.4.0-0ubuntu18.1 (Ubuntu 5.04)
- kdebase-doc-3.4.0-0ubuntu18.1 (Ubuntu 5.04)
- kdebase-kio-plugins-3.4.0-0ubuntu18.1 (Ubuntu 5.04)
- kdepasswd-3.4.0-0ubuntu18.1 (Ubuntu 5.04)
- kdeprint-3.4.0-0ubuntu18.1 (Ubuntu 5.04)
- 
[...]


Risk factor : High
';

if (description) {
script_id(20586);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "176-1");
script_summary(english:"kdebase vulnerability");
script_name(english:"USN176-1 : kdebase vulnerability");
script_cve_id("CVE-2005-2494");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "kappfinder", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kappfinder-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kappfinder-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kate", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kate-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kate-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kcontrol", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kcontrol-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kcontrol-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kdebase", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdebase-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdebase-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kdebase-bin", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdebase-bin-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdebase-bin-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kdebase-data", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdebase-data-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdebase-data-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kdebase-dev", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdebase-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdebase-dev-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kdebase-doc", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdebase-doc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdebase-doc-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kdebase-kio-plugins", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdebase-kio-plugins-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdebase-kio-plugins-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kdepasswd", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdepasswd-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdepasswd-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kdeprint", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdeprint-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdeprint-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kdesktop", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdesktop-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdesktop-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kdm", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdm-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdm-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kfind", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kfind-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kfind-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "khelpcenter", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package khelpcenter-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to khelpcenter-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kicker", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kicker-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kicker-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "klipper", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package klipper-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to klipper-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kmenuedit", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kmenuedit-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kmenuedit-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "konqueror", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package konqueror-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to konqueror-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "konqueror-nsplugins", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package konqueror-nsplugins-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to konqueror-nsplugins-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "konsole", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package konsole-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to konsole-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kpager", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kpager-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kpager-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kpersonalizer", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kpersonalizer-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kpersonalizer-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "ksmserver", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package ksmserver-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to ksmserver-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "ksplash", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package ksplash-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to ksplash-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "ksysguard", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package ksysguard-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to ksysguard-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "ksysguardd", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package ksysguardd-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to ksysguardd-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "ktip", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package ktip-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to ktip-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kwin", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kwin-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kwin-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libkonq4", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libkonq4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libkonq4-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libkonq4-dev", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libkonq4-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libkonq4-dev-3.4.0-0ubuntu18.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "xfonts-konsole", pkgver: "3.4.0-0ubuntu18.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xfonts-konsole-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to xfonts-konsole-3.4.0-0ubuntu18.1
');
}

if (w) { security_hole(port: 0, data: desc); }
