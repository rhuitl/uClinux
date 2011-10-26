# This script was automatically generated from the 93-1 Ubuntu Security Notice
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

A race condition was discovered in the handling of "Set-Cookie"
headers. If the obsolete Netscape recommendation was used for handling
cookies in the cache, it was possible for an attacker to steal the
cookies of other users.

Solution :

Upgrade to : 
- squid-2.5.5-6ubuntu0.6 (Ubuntu 4.10)
- squid-cgi-2.5.5-6ubuntu0.6 (Ubuntu 4.10)
- squid-common-2.5.5-6ubuntu0.6 (Ubuntu 4.10)
- squidclient-2.5.5-6ubuntu0.6 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20719);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "93-1");
script_summary(english:"squid vulnerability");
script_name(english:"USN93-1 : squid vulnerability");
script_cve_id("CVE-2005-0626");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "squid", pkgver: "2.5.5-6ubuntu0.6");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squid-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to squid-2.5.5-6ubuntu0.6
');
}
found = ubuntu_check(osver: "4.10", pkgname: "squid-cgi", pkgver: "2.5.5-6ubuntu0.6");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squid-cgi-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to squid-cgi-2.5.5-6ubuntu0.6
');
}
found = ubuntu_check(osver: "4.10", pkgname: "squid-common", pkgver: "2.5.5-6ubuntu0.6");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squid-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to squid-common-2.5.5-6ubuntu0.6
');
}
found = ubuntu_check(osver: "4.10", pkgname: "squidclient", pkgver: "2.5.5-6ubuntu0.6");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squidclient-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to squidclient-2.5.5-6ubuntu0.6
');
}

if (w) { security_hole(port: 0, data: desc); }
