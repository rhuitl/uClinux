# This script was automatically generated from the 124-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- mozilla-firefox 
- mozilla-firefox-dev 
- mozilla-firefox-dom-inspector 
- mozilla-firefox-gnome-support 


Description :

USN-124-1 fixed several vulnerabilities of Firefox. After that update,
several users experienced XML errors on various actions like adding
bookmarks (see https://bugzilla.ubuntu.com/show_bug.cgi?id=10643).
After installing these new packages and restarting the browser, these
problems should be fixed.

Solution :

Upgrade to : 
- mozilla-firefox-1.0.2-0ubuntu5.2 (Ubuntu 5.04)
- mozilla-firefox-dev-1.0.2-0ubuntu5.2 (Ubuntu 5.04)
- mozilla-firefox-dom-inspector-1.0.2-0ubuntu5.2 (Ubuntu 5.04)
- mozilla-firefox-gnome-support-1.0.2-0ubuntu5.2 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20514);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "124-2");
script_summary(english:"mozilla-firefox bug fix");
script_name(english:"USN124-2 : mozilla-firefox bug fix");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "mozilla-firefox", pkgver: "1.0.2-0ubuntu5.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-firefox-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-firefox-1.0.2-0ubuntu5.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-firefox-dev", pkgver: "1.0.2-0ubuntu5.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-firefox-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-firefox-dev-1.0.2-0ubuntu5.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-firefox-dom-inspector", pkgver: "1.0.2-0ubuntu5.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-firefox-dom-inspector-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-firefox-dom-inspector-1.0.2-0ubuntu5.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-firefox-gnome-support", pkgver: "1.0.2-0ubuntu5.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-firefox-gnome-support-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-firefox-gnome-support-1.0.2-0ubuntu5.2
');
}

if (w) { security_hole(port: 0, data: desc); }
