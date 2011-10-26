# This script was automatically generated from the 24-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libssl-dev 
- libssl0.9.7 
- openssl 


Description :

Recently, Trustix Secure Linux discovered a vulnerability in the
openssl package. The auxiliary script "der_chop" created temporary
files in an insecure way, which could allow a symlink attack to create
or overwrite arbitrary files with the privileges of the user invoking
the program.

Solution :

Upgrade to : 
- libssl-dev-0.9.7d-3ubuntu0.1 (Ubuntu 4.10)
- libssl0.9.7-0.9.7d-3ubuntu0.1 (Ubuntu 4.10)
- openssl-0.9.7d-3ubuntu0.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20639);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "24-1");
script_summary(english:"openssl script vulnerability");
script_name(english:"USN24-1 : openssl script vulnerability");
script_cve_id("CVE-2004-0975");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "libssl-dev", pkgver: "0.9.7d-3ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libssl-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libssl-dev-0.9.7d-3ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libssl0.9.7", pkgver: "0.9.7d-3ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libssl0.9.7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libssl0.9.7-0.9.7d-3ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "openssl", pkgver: "0.9.7d-3ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openssl-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to openssl-0.9.7d-3ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
