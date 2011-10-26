# This script was automatically generated from the 193-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- dia 
- dia-common 
- dia-gnome 
- dia-libs 


Description :

Joxean Koret discovered that the SVG import plugin did not properly
sanitise data read from an SVG file. By tricking an user into opening
a specially crafted SVG file, an attacker could exploit this to
execute arbitrary code with the privileges of the user.

Solution :

Upgrade to : 
- dia-0.94.0-5ubuntu1.1 (Ubuntu 5.04)
- dia-common-0.94.0-5ubuntu1.1 (Ubuntu 5.04)
- dia-gnome-0.94.0-5ubuntu1.1 (Ubuntu 5.04)
- dia-libs-0.94.0-5ubuntu1.1 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20607);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "193-1");
script_summary(english:"dia vulnerability");
script_name(english:"USN193-1 : dia vulnerability");
script_cve_id("CVE-2005-2966");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "dia", pkgver: "0.94.0-5ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package dia-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to dia-0.94.0-5ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "dia-common", pkgver: "0.94.0-5ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package dia-common-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to dia-common-0.94.0-5ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "dia-gnome", pkgver: "0.94.0-5ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package dia-gnome-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to dia-gnome-0.94.0-5ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "dia-libs", pkgver: "0.94.0-5ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package dia-libs-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to dia-libs-0.94.0-5ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
