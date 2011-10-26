# This script was automatically generated from the 19-1 Ubuntu Security Notice
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

Recently, two Denial of Service vulnerabilities have been discovered
in squid, a WWW proxy cache. Insufficient input validation in the NTLM
authentication handler allowed a remote attacker to crash the service
by sending a specially crafted NTLMSSP packet. Likewise, due to an
insufficient validation of ASN.1 headers, a remote attacker could
restart the server (causing all open connections to be dropped) by
sending certain SNMP packets with negative length fields.

Solution :

Upgrade to : 
- squid-2.5.5-6ubuntu0.2 (Ubuntu 4.10)
- squid-cgi-2.5.5-6ubuntu0.2 (Ubuntu 4.10)
- squid-common-2.5.5-6ubuntu0.2 (Ubuntu 4.10)
- squidclient-2.5.5-6ubuntu0.2 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20602);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "19-1");
script_summary(english:"squid vulnerabilities");
script_name(english:"USN19-1 : squid vulnerabilities");
script_cve_id("CVE-2004-0832","CVE-2004-0918");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "squid", pkgver: "2.5.5-6ubuntu0.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squid-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to squid-2.5.5-6ubuntu0.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "squid-cgi", pkgver: "2.5.5-6ubuntu0.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squid-cgi-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to squid-cgi-2.5.5-6ubuntu0.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "squid-common", pkgver: "2.5.5-6ubuntu0.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squid-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to squid-common-2.5.5-6ubuntu0.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "squidclient", pkgver: "2.5.5-6ubuntu0.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squidclient-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to squidclient-2.5.5-6ubuntu0.2
');
}

if (w) { security_hole(port: 0, data: desc); }
