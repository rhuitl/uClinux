# This script was automatically generated from the 214-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libungif-bin 
- libungif4-dev 
- libungif4g 


Description :

Chris Evans discovered several buffer overflows in the libungif
library. By tricking an user (or automated system) into processing a
specially crafted GIF image, this could be exploited to execute
arbitrary code with the privileges of the application using libungif.

Solution :

Upgrade to : 
- libungif-bin-4.1.3-2ubuntu0.1 (Ubuntu 5.10)
- libungif4-dev-4.1.3-2ubuntu0.1 (Ubuntu 5.10)
- libungif4g-4.1.3-2ubuntu0.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(20632);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "214-1");
script_summary(english:"libungif4 vulnerabilities");
script_name(english:"USN214-1 : libungif4 vulnerabilities");
script_cve_id("CVE-2005-2974","CVE-2005-3350");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "libungif-bin", pkgver: "4.1.3-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libungif-bin-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libungif-bin-4.1.3-2ubuntu0.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libungif4-dev", pkgver: "4.1.3-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libungif4-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libungif4-dev-4.1.3-2ubuntu0.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libungif4g", pkgver: "4.1.3-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libungif4g-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libungif4g-4.1.3-2ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
