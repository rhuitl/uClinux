# This script was automatically generated from the 277-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libtiff-opengl 
- libtiff-tools 
- libtiff4 
- libtiff4-dev 
- libtiffxx0c2 


Description :

Tavis Ormandy and Andrey Kiselev discovered that libtiff did not
sufficiently verify the validity of TIFF files. By tricking an user
into opening a specially crafted TIFF file with any application that
uses libtiff, an attacker could exploit this to crash the application
or even execute arbitrary code with the application\'s privileges.

Solution :

Upgrade to : 
- libtiff-opengl-3.7.3-1ubuntu1.1 (Ubuntu 5.10)
- libtiff-tools-3.7.3-1ubuntu1.1 (Ubuntu 5.10)
- libtiff4-3.7.3-1ubuntu1.1 (Ubuntu 5.10)
- libtiff4-dev-3.7.3-1ubuntu1.1 (Ubuntu 5.10)
- libtiffxx0c2-3.7.3-1ubuntu1.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(21371);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "277-1");
script_summary(english:"tiff vulnerabilities");
script_name(english:"USN277-1 : tiff vulnerabilities");
script_cve_id("CVE-2006-2024","CVE-2006-2025","CVE-2006-2026","CVE-2006-2120");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "libtiff-opengl", pkgver: "3.7.3-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libtiff-opengl-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libtiff-opengl-3.7.3-1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libtiff-tools", pkgver: "3.7.3-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libtiff-tools-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libtiff-tools-3.7.3-1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libtiff4", pkgver: "3.7.3-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libtiff4-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libtiff4-3.7.3-1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libtiff4-dev", pkgver: "3.7.3-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libtiff4-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libtiff4-dev-3.7.3-1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libtiffxx0c2", pkgver: "3.7.3-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libtiffxx0c2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libtiffxx0c2-3.7.3-1ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
