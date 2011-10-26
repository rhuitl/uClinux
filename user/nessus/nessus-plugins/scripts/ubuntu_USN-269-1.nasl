# This script was automatically generated from the 269-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- xscreensaver 
- xscreensaver-gl 
- xscreensaver-gnome 
- xscreensaver-nognome 


Description :

In some cases, xscreensaver did not properly grab the keyboard when
reading the password for unlocking the screen, so that the password
was typed into the currently active application window.

The only known vulnerable case was when xscreensaver activated while
an rdesktop session was currently active.

Solution :

Upgrade to : 
- xscreensaver-4.16-1ubuntu11.1 (Ubuntu 5.04)
- xscreensaver-gl-4.16-1ubuntu11.1 (Ubuntu 5.04)
- xscreensaver-gnome-4.16-1ubuntu11.1 (Ubuntu 5.04)
- xscreensaver-nognome-4.16-1ubuntu11.1 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(21216);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "269-1");
script_summary(english:"xscreensaver vulnerability");
script_name(english:"USN269-1 : xscreensaver vulnerability");
script_cve_id("CVE-2004-2655");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "xscreensaver", pkgver: "4.16-1ubuntu11.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xscreensaver-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to xscreensaver-4.16-1ubuntu11.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "xscreensaver-gl", pkgver: "4.16-1ubuntu11.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xscreensaver-gl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to xscreensaver-gl-4.16-1ubuntu11.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "xscreensaver-gnome", pkgver: "4.16-1ubuntu11.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xscreensaver-gnome-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to xscreensaver-gnome-4.16-1ubuntu11.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "xscreensaver-nognome", pkgver: "4.16-1ubuntu11.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xscreensaver-nognome-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to xscreensaver-nognome-4.16-1ubuntu11.1
');
}

if (w) { security_hole(port: 0, data: desc); }
