# This script was automatically generated from the 11-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libgd-tools 
- libgd2 
- libgd2-dev 
- libgd2-noxpm 
- libgd2-noxpm-dev 
- libgd2-xpm 
- libgd2-xpm-dev 


Description :

Several buffer overflows have been discovered in libgd\'s PNG handling
functions.

If an attacker tricked a user into loading a malicious PNG image, they
could leverage this into executing arbitrary code in the context of
the user opening image. Most importantly, this library is commonly
used in PHP. One possible target would be a PHP driven photo website
that lets users upload images. Therefore this vulnerability might lead
to privilege escalation to a web server\'s privileges.

Solution :

Upgrade to : 
- libgd-tools-2.0.23-2ubuntu0.1 (Ubuntu 4.10)
- libgd2-2.0.23-2ubuntu0.1 (Ubuntu 4.10)
- libgd2-dev-2.0.23-2ubuntu0.1 (Ubuntu 4.10)
- libgd2-noxpm-2.0.23-2ubuntu0.1 (Ubuntu 4.10)
- libgd2-noxpm-dev-2.0.23-2ubuntu0.1 (Ubuntu 4.10)
- libgd2-xpm-2.0.23-2ubuntu0.1 (Ubuntu 4.10)
- libgd2-xpm-dev-2.0.23-2ubuntu0.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20496);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "11-1");
script_summary(english:"libgd2 vulnerabilities");
script_name(english:"USN11-1 : libgd2 vulnerabilities");
script_cve_id("CVE-2004-0990");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "libgd-tools", pkgver: "2.0.23-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libgd-tools-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libgd-tools-2.0.23-2ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libgd2", pkgver: "2.0.23-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libgd2-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libgd2-2.0.23-2ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libgd2-dev", pkgver: "2.0.23-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libgd2-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libgd2-dev-2.0.23-2ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libgd2-noxpm", pkgver: "2.0.23-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libgd2-noxpm-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libgd2-noxpm-2.0.23-2ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libgd2-noxpm-dev", pkgver: "2.0.23-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libgd2-noxpm-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libgd2-noxpm-dev-2.0.23-2ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libgd2-xpm", pkgver: "2.0.23-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libgd2-xpm-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libgd2-xpm-2.0.23-2ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libgd2-xpm-dev", pkgver: "2.0.23-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libgd2-xpm-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libgd2-xpm-dev-2.0.23-2ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
