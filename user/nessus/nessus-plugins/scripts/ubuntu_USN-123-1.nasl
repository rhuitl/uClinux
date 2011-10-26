# This script was automatically generated from the 123-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libxine-dev 
- libxine1 


Description :

Two buffer overflows have been discovered in the MMS and Real RTSP
stream handlers of the Xine library. By tricking a user to connect to
a malicious MMS or RTSP video/audio stream source with an application
that uses this library, an attacker could crash the client and
possibly even execute arbitrary code with the privileges of the player
application.

Solution :

Upgrade to : 
- libxine-dev-1.0-1ubuntu3.1 (Ubuntu 5.04)
- libxine1-1.0-1ubuntu3.1 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20512);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "123-1");
script_summary(english:"xine-lib vulnerabilities");
script_name(english:"USN123-1 : xine-lib vulnerabilities");
script_cve_id("CVE-2005-1195");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "libxine-dev", pkgver: "1.0-1ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxine-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libxine-dev-1.0-1ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libxine1", pkgver: "1.0-1ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxine1-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libxine1-1.0-1ubuntu3.1
');
}

if (w) { security_hole(port: 0, data: desc); }
