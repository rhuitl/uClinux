# This script was automatically generated from the 54-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libtiff-tools 
- libtiff4 
- libtiff4-dev 


Description :

Dmitry V. Levin discovered a buffer overflow in the "tiffdump"
utility. If an attacker tricked a user into processing a malicious
TIFF image with tiffdump, they could cause a buffer overflow which at
least causes the program to crash. However, it is not entirely clear
whether this can be exploited to execute arbitrary code with the
privileges of the user opening the image.

Solution :

Upgrade to : 
- libtiff-tools-3.6.1-1.1ubuntu1.2 (Ubuntu 4.10)
- libtiff4-3.6.1-1.1ubuntu1.2 (Ubuntu 4.10)
- libtiff4-dev-3.6.1-1.1ubuntu1.2 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20672);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "54-1");
script_summary(english:"tiff vulnerability");
script_name(english:"USN54-1 : tiff vulnerability");
script_cve_id("CVE-2004-1183");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "libtiff-tools", pkgver: "3.6.1-1.1ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libtiff-tools-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libtiff-tools-3.6.1-1.1ubuntu1.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libtiff4", pkgver: "3.6.1-1.1ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libtiff4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libtiff4-3.6.1-1.1ubuntu1.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libtiff4-dev", pkgver: "3.6.1-1.1ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libtiff4-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libtiff4-dev-3.6.1-1.1ubuntu1.2
');
}

if (w) { security_hole(port: 0, data: desc); }
