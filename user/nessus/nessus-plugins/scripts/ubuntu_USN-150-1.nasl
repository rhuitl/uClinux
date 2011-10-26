# This script was automatically generated from the 150-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- kdelibs 
- kdelibs-bin 
- kdelibs-data 
- kdelibs4 
- kdelibs4-dev 
- kdelibs4-doc 


Description :

Kate and Kwrite create a backup file before saving a modified file.
These backup files were created with default permissions, even if the
original file had more strict permissions set, so that other local
users could possibly read the backup file even if they are not
permitted to read the original file.

Solution :

Upgrade to : 
- kdelibs-3.4.0-0ubuntu3.3 (Ubuntu 5.04)
- kdelibs-bin-3.4.0-0ubuntu3.3 (Ubuntu 5.04)
- kdelibs-data-3.4.0-0ubuntu3.3 (Ubuntu 5.04)
- kdelibs4-3.4.0-0ubuntu3.3 (Ubuntu 5.04)
- kdelibs4-dev-3.4.0-0ubuntu3.3 (Ubuntu 5.04)
- kdelibs4-doc-3.4.0-0ubuntu3.3 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20548);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "150-1");
script_summary(english:"kdelibs vulnerability");
script_name(english:"USN150-1 : kdelibs vulnerability");
script_cve_id("CVE-2005-1920");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "kdelibs", pkgver: "3.4.0-0ubuntu3.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdelibs-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdelibs-3.4.0-0ubuntu3.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kdelibs-bin", pkgver: "3.4.0-0ubuntu3.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdelibs-bin-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdelibs-bin-3.4.0-0ubuntu3.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kdelibs-data", pkgver: "3.4.0-0ubuntu3.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdelibs-data-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdelibs-data-3.4.0-0ubuntu3.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kdelibs4", pkgver: "3.4.0-0ubuntu3.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdelibs4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdelibs4-3.4.0-0ubuntu3.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kdelibs4-dev", pkgver: "3.4.0-0ubuntu3.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdelibs4-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdelibs4-dev-3.4.0-0ubuntu3.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kdelibs4-doc", pkgver: "3.4.0-0ubuntu3.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kdelibs4-doc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdelibs4-doc-3.4.0-0ubuntu3.3
');
}

if (w) { security_hole(port: 0, data: desc); }
