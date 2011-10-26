# This script was automatically generated from the 136-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- binutils 
- binutils-dev 
- binutils-doc 
- binutils-multiarch 


Description :

It was discovered that the packages from USN-136-1 had a flawed patch
with regressions that caused the ld linker to fail. The updated
packages fix this.

We apologize for the inconvenience.

Solution :

Upgrade to : 
- binutils-2.15-5ubuntu2.2 (Ubuntu 5.04)
- binutils-dev-2.15-5ubuntu2.2 (Ubuntu 5.04)
- binutils-doc-2.15-5ubuntu2.2 (Ubuntu 5.04)
- binutils-multiarch-2.15-5ubuntu2.2 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20528);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "136-2");
script_summary(english:"binutils regression");
script_name(english:"USN136-2 : binutils regression");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "binutils", pkgver: "2.15-5ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package binutils-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to binutils-2.15-5ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "binutils-dev", pkgver: "2.15-5ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package binutils-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to binutils-dev-2.15-5ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "binutils-doc", pkgver: "2.15-5ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package binutils-doc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to binutils-doc-2.15-5ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "binutils-multiarch", pkgver: "2.15-5ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package binutils-multiarch-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to binutils-multiarch-2.15-5ubuntu2.2
');
}

if (w) { security_hole(port: 0, data: desc); }
