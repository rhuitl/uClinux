# This script was automatically generated from the 140-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- gaim 
- gaim-data 
- gaim-dev 


Description :

A remote Denial of Service vulnerability was discovered in Gaim. A
remote attacker could crash the Gaim client of an MSN user by sending
a specially crafted MSN package which states an invalid body length in
the header.

Solution :

Upgrade to : 
- gaim-1.1.4-1ubuntu4.3 (Ubuntu 5.04)
- gaim-data-1.1.4-1ubuntu4.3 (Ubuntu 5.04)
- gaim-dev-1.1.4-1ubuntu4.3 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20533);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "140-1");
script_summary(english:"gaim vulnerability");
script_name(english:"USN140-1 : gaim vulnerability");
script_cve_id("CVE-2005-1934");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "gaim", pkgver: "1.1.4-1ubuntu4.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package gaim-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to gaim-1.1.4-1ubuntu4.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "gaim-data", pkgver: "1.1.4-1ubuntu4.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package gaim-data-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to gaim-data-1.1.4-1ubuntu4.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "gaim-dev", pkgver: "1.1.4-1ubuntu4.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package gaim-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to gaim-dev-1.1.4-1ubuntu4.3
');
}

if (w) { security_hole(port: 0, data: desc); }
