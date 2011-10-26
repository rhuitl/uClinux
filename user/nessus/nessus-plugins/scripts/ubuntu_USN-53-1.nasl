# This script was automatically generated from the 53-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- gdk-imlib1 
- gdk-imlib1-dev 
- imlib-base 
- imlib-progs 
- imlib1 
- imlib1-dev 


Description :

Pavel Kankovsky discovered several buffer overflows in imlib. If an
attacker tricked a user into loading a malicious image, he could
exploit this to execute arbitrary code in the context of the user
opening the image.

Solution :

Upgrade to : 
- gdk-imlib1-1.9.14-16ubuntu1.1 (Ubuntu 4.10)
- gdk-imlib1-dev-1.9.14-16ubuntu1.1 (Ubuntu 4.10)
- imlib-base-1.9.14-16ubuntu1.1 (Ubuntu 4.10)
- imlib-progs-1.9.14-16ubuntu1.1 (Ubuntu 4.10)
- imlib1-1.9.14-16ubuntu1.1 (Ubuntu 4.10)
- imlib1-dev-1.9.14-16ubuntu1.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20671);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "53-1");
script_summary(english:"imlib+png2 vulnerabilities");
script_name(english:"USN53-1 : imlib+png2 vulnerabilities");
script_cve_id("CVE-2004-1025","CVE-2004-1026");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "gdk-imlib1", pkgver: "1.9.14-16ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package gdk-imlib1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to gdk-imlib1-1.9.14-16ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "gdk-imlib1-dev", pkgver: "1.9.14-16ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package gdk-imlib1-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to gdk-imlib1-dev-1.9.14-16ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "imlib-base", pkgver: "1.9.14-16ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package imlib-base-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to imlib-base-1.9.14-16ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "imlib-progs", pkgver: "1.9.14-16ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package imlib-progs-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to imlib-progs-1.9.14-16ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "imlib1", pkgver: "1.9.14-16ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package imlib1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to imlib1-1.9.14-16ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "imlib1-dev", pkgver: "1.9.14-16ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package imlib1-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to imlib1-dev-1.9.14-16ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
