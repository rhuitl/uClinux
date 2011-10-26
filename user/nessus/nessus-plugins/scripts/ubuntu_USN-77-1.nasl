# This script was automatically generated from the 77-1 Ubuntu Security Notice
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

A possible authentication bypass was discovered in the LDAP
authentication backend. LDAP ignores leading and trailing whitespace
in search filters. This could possibly be abused to bypass explicit
access controls or confuse accounting when using several variants of
the login name. (CVE-2005-0173)

Previous Squid versions were not strict enough while parsing HTTP
requests and responses. Various violations of the HTTP protocol, such
as multiple Content-Length header lines, invalid "Carriage Return"
characters, and HTTP header names containing whitespace, led to cache
pollution and could possibly be exploited to deliver wrong content to
clients. (CVE-2005-0174)

Squid was susceptible to a cache poisoning attack called "HTTP
response splitting", where false replies are injected in the HTTP
stream. This allowed malicious web servers to forge wrong cache
content for arbitrary web sites, which was then delivered to Squid
clients. (CVE-2005-0175)

The FSC Vulnerability Research Team discovered a buffer overflow in
t
[...]

Solution :

Upgrade to : 
- squid-2.5.5-6ubuntu0.4 (Ubuntu 4.10)
- squid-cgi-2.5.5-6ubuntu0.4 (Ubuntu 4.10)
- squid-common-2.5.5-6ubuntu0.4 (Ubuntu 4.10)
- squidclient-2.5.5-6ubuntu0.4 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20699);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "77-1");
script_summary(english:"squid vulnerabilities");
script_name(english:"USN77-1 : squid vulnerabilities");
script_cve_id("CVE-2005-0173","CVE-2005-0174","CVE-2005-0175","CVE-2005-0211");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "squid", pkgver: "2.5.5-6ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squid-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to squid-2.5.5-6ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "squid-cgi", pkgver: "2.5.5-6ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squid-cgi-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to squid-cgi-2.5.5-6ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "squid-common", pkgver: "2.5.5-6ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squid-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to squid-common-2.5.5-6ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "squidclient", pkgver: "2.5.5-6ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squidclient-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to squidclient-2.5.5-6ubuntu0.4
');
}

if (w) { security_hole(port: 0, data: desc); }
