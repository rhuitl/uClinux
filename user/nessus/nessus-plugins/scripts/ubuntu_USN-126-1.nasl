# This script was automatically generated from the 126-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- gnutls-bin 
- libgnutls-doc 
- libgnutls10 
- libgnutls10-dev 
- libgnutls11 
- libgnutls11-dbg 
- libgnutls11-dev 


Description :

A Denial of Service vulnerability was discovered in the GNU TLS
library, which provides common cryptographic algorithms and is used by
many applications in Ubuntu. Due to a missing sanity check of the
padding length field, specially crafted ciphertext blocks caused an
out of bounds memory access which could crash the application. It was
not possible to exploit this to execute any attacker specified code.

Solution :

Upgrade to : 
- gnutls-bin-1.0.16-13ubuntu0.1 (Ubuntu 5.04)
- libgnutls-doc-1.0.4-3ubuntu1.1 (Ubuntu 4.10)
- libgnutls10-1.0.4-3ubuntu1.1 (Ubuntu 4.10)
- libgnutls10-dev-1.0.4-3ubuntu1.1 (Ubuntu 4.10)
- libgnutls11-1.0.16-13ubuntu0.1 (Ubuntu 5.04)
- libgnutls11-dbg-1.0.16-13ubuntu0.1 (Ubuntu 5.04)
- libgnutls11-dev-1.0.16-13ubuntu0.1 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20516);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "126-1");
script_summary(english:"gnutls11, gnutls10 vulnerability");
script_name(english:"USN126-1 : gnutls11, gnutls10 vulnerability");
script_cve_id("CVE-2005-1431");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "gnutls-bin", pkgver: "1.0.16-13ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package gnutls-bin-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to gnutls-bin-1.0.16-13ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libgnutls-doc", pkgver: "1.0.4-3ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libgnutls-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libgnutls-doc-1.0.4-3ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libgnutls10", pkgver: "1.0.4-3ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libgnutls10-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libgnutls10-1.0.4-3ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libgnutls10-dev", pkgver: "1.0.4-3ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libgnutls10-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libgnutls10-dev-1.0.4-3ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libgnutls11", pkgver: "1.0.16-13ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libgnutls11-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libgnutls11-1.0.16-13ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libgnutls11-dbg", pkgver: "1.0.16-13ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libgnutls11-dbg-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libgnutls11-dbg-1.0.16-13ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libgnutls11-dev", pkgver: "1.0.16-13ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libgnutls11-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libgnutls11-dev-1.0.16-13ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
