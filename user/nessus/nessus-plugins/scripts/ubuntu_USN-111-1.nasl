# This script was automatically generated from the 111-1 Ubuntu Security Notice
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

A remote Denial of Service vulnerability has been discovered in Squid.
If the remote end aborted the connection during a PUT or POST request,
Squid tried to free an already freed part of memory, which eventually
caused the server to crash.

Solution :

Upgrade to : 
- squid-2.5.5-6ubuntu0.7 (Ubuntu 4.10)
- squid-cgi-2.5.5-6ubuntu0.7 (Ubuntu 4.10)
- squid-common-2.5.5-6ubuntu0.7 (Ubuntu 4.10)
- squidclient-2.5.5-6ubuntu0.7 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20498);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "111-1");
script_summary(english:"squid vulnerability");
script_name(english:"USN111-1 : squid vulnerability");
script_cve_id("CVE-2005-0718");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "squid", pkgver: "2.5.5-6ubuntu0.7");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squid-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to squid-2.5.5-6ubuntu0.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "squid-cgi", pkgver: "2.5.5-6ubuntu0.7");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squid-cgi-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to squid-cgi-2.5.5-6ubuntu0.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "squid-common", pkgver: "2.5.5-6ubuntu0.7");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squid-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to squid-common-2.5.5-6ubuntu0.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "squidclient", pkgver: "2.5.5-6ubuntu0.7");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squidclient-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to squidclient-2.5.5-6ubuntu0.7
');
}

if (w) { security_hole(port: 0, data: desc); }
