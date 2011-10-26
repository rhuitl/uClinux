# This script was automatically generated from the 192-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- squid 
- squid-cgi 
- squid-common 
- squidclient 


Description :

Mike Diggins discovered a remote Denial of Service vulnerability in
Squid. Sending specially crafted NTML authentication requests to Squid
caused the server to crash.

Solution :

Upgrade to : 
- squid-2.5.8-3ubuntu1.4 (Ubuntu 5.04)
- squid-cgi-2.5.8-3ubuntu1.4 (Ubuntu 5.04)
- squid-common-2.5.8-3ubuntu1.4 (Ubuntu 5.04)
- squidclient-2.5.8-3ubuntu1.4 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20606);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "192-1");
script_summary(english:"squid vulnerability");
script_name(english:"USN192-1 : squid vulnerability");
script_cve_id("CVE-2005-2917");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "squid", pkgver: "2.5.8-3ubuntu1.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squid-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to squid-2.5.8-3ubuntu1.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "squid-cgi", pkgver: "2.5.8-3ubuntu1.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squid-cgi-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to squid-cgi-2.5.8-3ubuntu1.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "squid-common", pkgver: "2.5.8-3ubuntu1.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squid-common-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to squid-common-2.5.8-3ubuntu1.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "squidclient", pkgver: "2.5.8-3ubuntu1.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squidclient-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to squidclient-2.5.8-3ubuntu1.4
');
}

if (w) { security_hole(port: 0, data: desc); }
