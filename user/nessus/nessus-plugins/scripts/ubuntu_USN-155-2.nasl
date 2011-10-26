# This script was automatically generated from the 155-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- epiphany-browser 
- epiphany-browser-dev 


Description :

USN-155-1 fixed some security vulnerabilities of the Mozilla suite.
Unfortunately this update caused regressions in the Epiphany web
browser, which uses parts of the Mozilla browser. The updated packages
fix these problems.

Solution :

Upgrade to : 
- epiphany-browser-1.4.4-0ubuntu2.1 (Ubuntu 4.10)
- epiphany-browser-dev-1.4.4-0ubuntu2.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20557);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "155-2");
script_summary(english:"epiphany-browser regressions");
script_name(english:"USN155-2 : epiphany-browser regressions");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "epiphany-browser", pkgver: "1.4.4-0ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package epiphany-browser-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to epiphany-browser-1.4.4-0ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "epiphany-browser-dev", pkgver: "1.4.4-0ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package epiphany-browser-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to epiphany-browser-dev-1.4.4-0ubuntu2.1
');
}

if (w) { security_hole(port: 0, data: desc); }
