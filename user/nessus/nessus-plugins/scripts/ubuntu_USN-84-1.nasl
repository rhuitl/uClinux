# This script was automatically generated from the 84-1 Ubuntu Security Notice
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

When parsing the configuration file, squid interpreted empty Access
Control Lists (ACLs) without defined authentication schemes in a
non-obvious way. This could allow remote attackers to bypass intended
ACLs. (CVE-2005-0194)

A remote Denial of Service vulnerability was discovered in the domain
name resolution code. A faulty or malicious DNS server could stop the
Squid server immediately by sending a malformed IP address.
(CVE-2005-0446)

Solution :

Upgrade to : 
- squid-2.5.5-6ubuntu0.5 (Ubuntu 4.10)
- squid-cgi-2.5.5-6ubuntu0.5 (Ubuntu 4.10)
- squid-common-2.5.5-6ubuntu0.5 (Ubuntu 4.10)
- squidclient-2.5.5-6ubuntu0.5 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20709);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "84-1");
script_summary(english:"squid vulnerabilities");
script_name(english:"USN84-1 : squid vulnerabilities");
script_cve_id("CVE-2005-0194","CVE-2005-0446");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "squid", pkgver: "2.5.5-6ubuntu0.5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squid-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to squid-2.5.5-6ubuntu0.5
');
}
found = ubuntu_check(osver: "4.10", pkgname: "squid-cgi", pkgver: "2.5.5-6ubuntu0.5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squid-cgi-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to squid-cgi-2.5.5-6ubuntu0.5
');
}
found = ubuntu_check(osver: "4.10", pkgname: "squid-common", pkgver: "2.5.5-6ubuntu0.5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squid-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to squid-common-2.5.5-6ubuntu0.5
');
}
found = ubuntu_check(osver: "4.10", pkgname: "squidclient", pkgver: "2.5.5-6ubuntu0.5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squidclient-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to squidclient-2.5.5-6ubuntu0.5
');
}

if (w) { security_hole(port: 0, data: desc); }
