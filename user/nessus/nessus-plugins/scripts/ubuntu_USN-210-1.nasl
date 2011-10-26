# This script was automatically generated from the 210-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libnetpbm10 
- libnetpbm10-dev 
- libnetpbm9 
- libnetpbm9-dev 
- netpbm 


Description :

A buffer overflow was found in the "pnmtopng" conversion program. By
tricking an user (or automated system) to process a specially crafted
PNM image with pnmtopng, this could be exploited to execute arbitrary
code with the privileges of the user running pnmtopng.

Solution :

Upgrade to : 
- libnetpbm10-10.0-8ubuntu1.1 (Ubuntu 5.10)
- libnetpbm10-dev-10.0-8ubuntu1.1 (Ubuntu 5.10)
- libnetpbm9-10.0-8ubuntu1.1 (Ubuntu 5.10)
- libnetpbm9-dev-10.0-8ubuntu1.1 (Ubuntu 5.10)
- netpbm-10.0-8ubuntu1.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(20628);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "210-1");
script_summary(english:"netpbm-free vulnerability");
script_name(english:"USN210-1 : netpbm-free vulnerability");
script_cve_id("CVE-2005-2978");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "libnetpbm10", pkgver: "10.0-8ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libnetpbm10-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnetpbm10-10.0-8ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libnetpbm10-dev", pkgver: "10.0-8ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libnetpbm10-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnetpbm10-dev-10.0-8ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libnetpbm9", pkgver: "10.0-8ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libnetpbm9-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnetpbm9-10.0-8ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libnetpbm9-dev", pkgver: "10.0-8ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libnetpbm9-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnetpbm9-dev-10.0-8ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "netpbm", pkgver: "10.0-8ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package netpbm-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to netpbm-10.0-8ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
