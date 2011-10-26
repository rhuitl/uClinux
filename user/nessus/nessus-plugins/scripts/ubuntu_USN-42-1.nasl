# This script was automatically generated from the 42-1 Ubuntu Security Notice
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

Several buffer overflows have been discovered in xine-lib, the
video/audio codec library for Xine frontends (xine-ui, totem-xine,
kaffeine, and others). If an attacker tricked a user into loading a
malicious RTSP stream or a stream with specially crafted AIFF audio or
PNM image data, they could exploit this to execute arbitrary code with
the privileges of the user opening the audio/video file.

Solution :

Upgrade to : 
- libxine-dev-1-rc5-1ubuntu2.1 (Ubuntu 4.10)
- libxine1-1-rc5-1ubuntu2.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20659);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "42-1");
script_summary(english:"xine-lib vulnerabilities");
script_name(english:"USN42-1 : xine-lib vulnerabilities");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "libxine-dev", pkgver: "1-rc5-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxine-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxine-dev-1-rc5-1ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxine1", pkgver: "1-rc5-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxine1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxine1-1-rc5-1ubuntu2.1
');
}

if (w) { security_hole(port: 0, data: desc); }
