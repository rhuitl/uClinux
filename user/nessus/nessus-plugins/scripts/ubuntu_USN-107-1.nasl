# This script was automatically generated from the 107-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- ipsec-tools 
- racoon 


Description :

Sebastian Krahmer discovered a Denial of Service vulnerability in the
racoon daemon. By sending specially crafted ISAKMP packets, a remote
attacker could trigger a buffer overflow which caused racoon to crash.

This update does not introduce any source code changes affecting the
ipsec-tools package.  It is necessary to update the version number of
the package in order to support an update to the "racoon" package.
Please note that racoon is not officially supported by Ubuntu (it is
in the "universe" component of the archive).

Solution :

Upgrade to : 
- ipsec-tools-0.3.3-1ubuntu0.1 (Ubuntu 4.10)
- racoon-0.3.3-1ubuntu0.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20493);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "107-1");
script_summary(english:"ipsec-tools vulnerability");
script_name(english:"USN107-1 : ipsec-tools vulnerability");
script_cve_id("CVE-2005-0398");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "ipsec-tools", pkgver: "0.3.3-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package ipsec-tools-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to ipsec-tools-0.3.3-1ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "racoon", pkgver: "0.3.3-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package racoon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to racoon-0.3.3-1ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
