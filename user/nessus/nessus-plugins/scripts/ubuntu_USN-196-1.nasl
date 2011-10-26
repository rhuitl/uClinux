# This script was automatically generated from the 196-1 Ubuntu Security Notice
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

Ulf Harnhammar discovered a format string vulnerability in the CDDB
module\'s cache file handling in the Xine library, which is
used by packages such as xine-ui, totem-xine, and gxine.

By tricking an user into playing a particular audio CD which has a
specially-crafted CDDB entry, a remote attacker could exploit this
vulnerability to execute arbitrary code with the privileges of the
user running the application. Since CDDB servers usually allow anybody
to add and modify information, this exploit does not even require a
particular CDDB server to be selected.

Solution :

Upgrade to : 
- libxine-dev-1.0-1ubuntu3.1.1 (Ubuntu 5.04)
- libxine1-1.0-1ubuntu3.1.1 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20610);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "196-1");
script_summary(english:"xine-lib vulnerability");
script_name(english:"USN196-1 : xine-lib vulnerability");
script_cve_id("CVE-2005-2337");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "libxine-dev", pkgver: "1.0-1ubuntu3.1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxine-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libxine-dev-1.0-1ubuntu3.1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libxine1", pkgver: "1.0-1ubuntu3.1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxine1-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libxine1-1.0-1ubuntu3.1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
