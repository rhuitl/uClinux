# This script was automatically generated from the 218-1 Ubuntu Security Notice
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

Two buffer overflows were discovered in the \'pnmtopng\' tool, which
were triggered by processing an image with exactly 256 colors when
using the -alpha option (CVE-2005-3662) or by processing a text file
with very long lines when using the -text option (CVE-2005-3632).

A remote attacker could exploit these to execute arbitrary code by
tricking an user or an automated system into processing a specially
crafted PNM file with pnmtopng.

Solution :

Upgrade to : 
- libnetpbm10-10.0-8ubuntu1.2 (Ubuntu 5.10)
- libnetpbm10-dev-10.0-8ubuntu1.2 (Ubuntu 5.10)
- libnetpbm9-10.0-8ubuntu1.2 (Ubuntu 5.10)
- libnetpbm9-dev-10.0-8ubuntu1.2 (Ubuntu 5.10)
- netpbm-10.0-8ubuntu1.2 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(20636);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "218-1");
script_summary(english:"netpbm-free vulnerabilities");
script_name(english:"USN218-1 : netpbm-free vulnerabilities");
script_cve_id("CVE-2005-3632","CVE-2005-3662");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "libnetpbm10", pkgver: "10.0-8ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libnetpbm10-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnetpbm10-10.0-8ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libnetpbm10-dev", pkgver: "10.0-8ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libnetpbm10-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnetpbm10-dev-10.0-8ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libnetpbm9", pkgver: "10.0-8ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libnetpbm9-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnetpbm9-10.0-8ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libnetpbm9-dev", pkgver: "10.0-8ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libnetpbm9-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnetpbm9-dev-10.0-8ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "netpbm", pkgver: "10.0-8ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package netpbm-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to netpbm-10.0-8ubuntu1.2
');
}

if (w) { security_hole(port: 0, data: desc); }
