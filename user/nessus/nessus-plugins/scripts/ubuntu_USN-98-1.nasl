# This script was automatically generated from the 98-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libslp-dev 
- libslp1 
- openslp-doc 
- slpd 
- slptool 


Description :

The SuSE Security Team discovered several buffer overflows in the
OpenSLP server and client library. By sending specially crafted SLP
packets, a remote attacker could exploit this to crash the SLP server
or execute arbitrary code with the privileges of the "daemon" user.
Likewise, a malicious SLP server could exploit the client library
vulnerabilities to execute arbitrary code with the privileges of the
user running the SLP client application.

Solution :

Upgrade to : 
- libslp-dev-1.0.11-7ubuntu0.1 (Ubuntu 4.10)
- libslp1-1.0.11-7ubuntu0.1 (Ubuntu 4.10)
- openslp-doc-1.0.11-7ubuntu0.1 (Ubuntu 4.10)
- slpd-1.0.11-7ubuntu0.1 (Ubuntu 4.10)
- slptool-1.0.11-7ubuntu0.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20724);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "98-1");
script_summary(english:"openslp vulnerabilities");
script_name(english:"USN98-1 : openslp vulnerabilities");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "libslp-dev", pkgver: "1.0.11-7ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libslp-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libslp-dev-1.0.11-7ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libslp1", pkgver: "1.0.11-7ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libslp1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libslp1-1.0.11-7ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "openslp-doc", pkgver: "1.0.11-7ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openslp-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to openslp-doc-1.0.11-7ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "slpd", pkgver: "1.0.11-7ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package slpd-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to slpd-1.0.11-7ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "slptool", pkgver: "1.0.11-7ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package slptool-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to slptool-1.0.11-7ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
