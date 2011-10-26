# This script was automatically generated from the 268-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- kaffeine 
- kaffeine-gstreamer 
- kaffeine-xine 


Description :

Marcus Meissner discovered a buffer overflow in the http_peek()
function. By tricking an user into opening a specially crafted
playlist URL with Kaffeine, a remote attacker could exploit this to
execute arbitrary code with the user\'s privileges.

Solution :

Upgrade to : 
- kaffeine-0.7-0ubuntu4.1 (Ubuntu 5.10)
- kaffeine-gstreamer-0.7-0ubuntu4.1 (Ubuntu 5.10)
- kaffeine-xine-0.7-0ubuntu4.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(21204);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "268-1");
script_summary(english:"kaffeine vulnerability");
script_name(english:"USN268-1 : kaffeine vulnerability");
script_cve_id("CVE-2006-0051");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "kaffeine", pkgver: "0.7-0ubuntu4.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kaffeine-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kaffeine-0.7-0ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kaffeine-gstreamer", pkgver: "0.7-0ubuntu4.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kaffeine-gstreamer-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kaffeine-gstreamer-0.7-0ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kaffeine-xine", pkgver: "0.7-0ubuntu4.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kaffeine-xine-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kaffeine-xine-0.7-0ubuntu4.1
');
}

if (w) { security_hole(port: 0, data: desc); }
