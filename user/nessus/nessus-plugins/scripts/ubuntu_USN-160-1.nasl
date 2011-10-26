# This script was automatically generated from the 160-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- apache2 
- apache2-common 
- apache2-doc 
- apache2-mpm-perchild 
- apache2-mpm-prefork 
- apache2-mpm-threadpool 
- apache2-mpm-worker 
- apache2-prefork-dev 
- apache2-threaded-dev 
- apache2-utils 
- libapr0 
- libapr0-dev 


Description :

Marc Stern discovered a buffer overflow in the SSL module\'s
certificate revocation list (CRL) handler. If Apache is configured to
use a malicious CRL, this could possibly lead to a server crash or
arbitrary code execution with the privileges of the Apache web server.
(CVE-2005-1268)

Watchfire discovered that Apache insufficiently verified the
"Transfer-Encoding" and "Content-Length" headers when acting as an
HTTP proxy. By sending a specially crafted HTTP request, a remote
attacker who is authorized to use the proxy could exploit this to
bypass web application firewalls, poison the HTTP proxy cache, and
conduct cross-site scripting attacks against other proxy users.
(CVE-2005-2088)

Solution :

Upgrade to : 
- apache2-2.0.53-5ubuntu5.2 (Ubuntu 5.04)
- apache2-common-2.0.53-5ubuntu5.2 (Ubuntu 5.04)
- apache2-doc-2.0.53-5ubuntu5.2 (Ubuntu 5.04)
- apache2-mpm-perchild-2.0.53-5ubuntu5.2 (Ubuntu 5.04)
- apache2-mpm-prefork-2.0.53-5ubuntu5.2 (Ubuntu 5.04)
- apache2-mpm-threadpool-2.0.53-5ubuntu5.2 (Ubuntu 5.04)
- apache2-mpm-worker-2.0.53-5ubuntu5.2 (Ubuntu 5.04)
- apache2-prefork-dev-2.0.53-5ubuntu5.2 (Ubuntu 5.04)
- apache2-threaded-dev-2.0.53-5ubuntu5.2 (Ubuntu 5.04)
- apache2-utils-2.0.53-5ubuntu5.
[...]


Risk factor : High
';

if (description) {
script_id(20565);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "160-1");
script_summary(english:"apache2 vulnerabilities");
script_name(english:"USN160-1 : apache2 vulnerabilities");
script_cve_id("CVE-2005-1268","CVE-2005-2088");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "apache2", pkgver: "2.0.53-5ubuntu5.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache2-2.0.53-5ubuntu5.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "apache2-common", pkgver: "2.0.53-5ubuntu5.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-common-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache2-common-2.0.53-5ubuntu5.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "apache2-doc", pkgver: "2.0.53-5ubuntu5.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-doc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache2-doc-2.0.53-5ubuntu5.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "apache2-mpm-perchild", pkgver: "2.0.53-5ubuntu5.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-mpm-perchild-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache2-mpm-perchild-2.0.53-5ubuntu5.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "apache2-mpm-prefork", pkgver: "2.0.53-5ubuntu5.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-mpm-prefork-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache2-mpm-prefork-2.0.53-5ubuntu5.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "apache2-mpm-threadpool", pkgver: "2.0.53-5ubuntu5.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-mpm-threadpool-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache2-mpm-threadpool-2.0.53-5ubuntu5.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "apache2-mpm-worker", pkgver: "2.0.53-5ubuntu5.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-mpm-worker-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache2-mpm-worker-2.0.53-5ubuntu5.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "apache2-prefork-dev", pkgver: "2.0.53-5ubuntu5.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-prefork-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache2-prefork-dev-2.0.53-5ubuntu5.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "apache2-threaded-dev", pkgver: "2.0.53-5ubuntu5.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-threaded-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache2-threaded-dev-2.0.53-5ubuntu5.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "apache2-utils", pkgver: "2.0.53-5ubuntu5.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-utils-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache2-utils-2.0.53-5ubuntu5.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libapr0", pkgver: "2.0.53-5ubuntu5.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libapr0-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libapr0-2.0.53-5ubuntu5.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libapr0-dev", pkgver: "2.0.53-5ubuntu5.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libapr0-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libapr0-dev-2.0.53-5ubuntu5.2
');
}

if (w) { security_hole(port: 0, data: desc); }
