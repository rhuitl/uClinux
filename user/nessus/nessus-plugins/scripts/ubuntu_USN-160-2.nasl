# This script was automatically generated from the 160-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- apache 
- apache-common 
- apache-dbg 
- apache-dev 
- apache-doc 
- apache-perl 
- apache-ssl 
- apache-utils 
- libapache-mod-perl 


Description :

USN-160-1 fixed two vulnerabilities in the Apache 2 server. The old
Apache 1 server was also vulnerable to one of the vulnerabilities
(CVE-2005-2088). Please note that Apache 1 is not officially supported
in Ubuntu (it is in the "universe" component of the archive).

For reference, this is the relevant part of the original advisory:

  Watchfire discovered that Apache insufficiently verified the
  "Transfer-Encoding" and "Content-Length" headers when acting as an
  HTTP proxy. By sending a specially crafted HTTP request, a remote
  attacker who is authorized to use the proxy could exploit this to
  bypass web application firewalls, poison the HTTP proxy cache, and
  conduct cross-site scripting attacks against other proxy users.
  (CVE-2005-2088)

Solution :

Upgrade to : 
- apache-1.3.33-4ubuntu1 (Ubuntu 5.04)
- apache-common-1.3.33-4ubuntu1 (Ubuntu 5.04)
- apache-dbg-1.3.33-4ubuntu1 (Ubuntu 5.04)
- apache-dev-1.3.33-4ubuntu1 (Ubuntu 5.04)
- apache-doc-1.3.33-4ubuntu1 (Ubuntu 5.04)
- apache-perl-1.3.33-4ubuntu1 (Ubuntu 5.04)
- apache-ssl-1.3.33-4ubuntu1 (Ubuntu 5.04)
- apache-utils-1.3.33-4ubuntu1 (Ubuntu 5.04)
- libapache-mod-perl-1.29.0.3-4ubuntu1 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20566);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "160-2");
script_summary(english:"apache vulnerability");
script_name(english:"USN160-2 : apache vulnerability");
script_cve_id("CVE-2005-2088");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "apache", pkgver: "1.3.33-4ubuntu1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache-1.3.33-4ubuntu1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "apache-common", pkgver: "1.3.33-4ubuntu1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache-common-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache-common-1.3.33-4ubuntu1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "apache-dbg", pkgver: "1.3.33-4ubuntu1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache-dbg-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache-dbg-1.3.33-4ubuntu1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "apache-dev", pkgver: "1.3.33-4ubuntu1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache-dev-1.3.33-4ubuntu1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "apache-doc", pkgver: "1.3.33-4ubuntu1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache-doc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache-doc-1.3.33-4ubuntu1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "apache-perl", pkgver: "1.3.33-4ubuntu1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache-perl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache-perl-1.3.33-4ubuntu1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "apache-ssl", pkgver: "1.3.33-4ubuntu1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache-ssl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache-ssl-1.3.33-4ubuntu1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "apache-utils", pkgver: "1.3.33-4ubuntu1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache-utils-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache-utils-1.3.33-4ubuntu1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libapache-mod-perl", pkgver: "1.29.0.3-4ubuntu1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libapache-mod-perl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libapache-mod-perl-1.29.0.3-4ubuntu1
');
}

if (w) { security_hole(port: 0, data: desc); }
