# This script was automatically generated from the 177-1 Ubuntu Security Notice
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
- libapache-mod-ssl 
- libapache-mod-ssl-doc 
- libapr0 
- libapr0-dev 


Description :

Apache did not honour the "SSLVerifyClient require" directive within a
<Location> block if the surrounding <VirtualHost> block contained a
directive "SSLVerifyClient optional". This allowed clients to bypass
client certificate validation on servers with the above configuration.
(CVE-2005-2700)

Filip Sneppe discovered a Denial of Service vulnerability in the byte
range filter handler. By requesting certain large byte ranges, a
remote attacker could cause memory exhaustion in the server.
(CVE-2005-2728)

The updated libapache-mod-ssl also fixes two older Denial of Service
vulnerabilities: A format string error in the ssl_log() function which
could be exploited to crash the server (CVE-2004-0700), and a flaw in
the SSL cipher negotiation which could be exploited to terminate a
session (CVE-2004-0885). Please note that Apache 1.3 and
libapache-mod-ssl are not officially supported (they are in the
"universe" component of the Ubuntu archive).

Solution :

Upgrade to : 
- apache2-2.0.53-5ubuntu5.3 (Ubuntu 5.04)
- apache2-common-2.0.53-5ubuntu5.3 (Ubuntu 5.04)
- apache2-doc-2.0.53-5ubuntu5.3 (Ubuntu 5.04)
- apache2-mpm-perchild-2.0.53-5ubuntu5.3 (Ubuntu 5.04)
- apache2-mpm-prefork-2.0.53-5ubuntu5.3 (Ubuntu 5.04)
- apache2-mpm-threadpool-2.0.53-5ubuntu5.3 (Ubuntu 5.04)
- apache2-mpm-worker-2.0.53-5ubuntu5.3 (Ubuntu 5.04)
- apache2-prefork-dev-2.0.53-5ubuntu5.3 (Ubuntu 5.04)
- apache2-threaded-dev-2.0.53-5ubuntu5.3 (Ubuntu 5.04)
- apache2-utils-2.0.53-5ubuntu5.
[...]


Risk factor : High
';

if (description) {
script_id(20587);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "177-1");
script_summary(english:"apache2, libapache-mod-ssl vulnerabilities");
script_name(english:"USN177-1 : apache2, libapache-mod-ssl vulnerabilities");
script_cve_id("CVE-2004-0700","CVE-2004-0885","CVE-2005-2700","CVE-2005-2728");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "apache2", pkgver: "2.0.53-5ubuntu5.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache2-2.0.53-5ubuntu5.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "apache2-common", pkgver: "2.0.53-5ubuntu5.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-common-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache2-common-2.0.53-5ubuntu5.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "apache2-doc", pkgver: "2.0.53-5ubuntu5.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-doc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache2-doc-2.0.53-5ubuntu5.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "apache2-mpm-perchild", pkgver: "2.0.53-5ubuntu5.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-mpm-perchild-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache2-mpm-perchild-2.0.53-5ubuntu5.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "apache2-mpm-prefork", pkgver: "2.0.53-5ubuntu5.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-mpm-prefork-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache2-mpm-prefork-2.0.53-5ubuntu5.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "apache2-mpm-threadpool", pkgver: "2.0.53-5ubuntu5.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-mpm-threadpool-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache2-mpm-threadpool-2.0.53-5ubuntu5.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "apache2-mpm-worker", pkgver: "2.0.53-5ubuntu5.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-mpm-worker-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache2-mpm-worker-2.0.53-5ubuntu5.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "apache2-prefork-dev", pkgver: "2.0.53-5ubuntu5.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-prefork-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache2-prefork-dev-2.0.53-5ubuntu5.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "apache2-threaded-dev", pkgver: "2.0.53-5ubuntu5.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-threaded-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache2-threaded-dev-2.0.53-5ubuntu5.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "apache2-utils", pkgver: "2.0.53-5ubuntu5.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-utils-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to apache2-utils-2.0.53-5ubuntu5.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libapache-mod-ssl", pkgver: "2.8.22-1ubuntu1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libapache-mod-ssl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libapache-mod-ssl-2.8.22-1ubuntu1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libapache-mod-ssl-doc", pkgver: "2.8.22-1ubuntu1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libapache-mod-ssl-doc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libapache-mod-ssl-doc-2.8.22-1ubuntu1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libapr0", pkgver: "2.0.53-5ubuntu5.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libapr0-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libapr0-2.0.53-5ubuntu5.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libapr0-dev", pkgver: "2.0.53-5ubuntu5.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libapr0-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libapr0-dev-2.0.53-5ubuntu5.3
');
}

if (w) { security_hole(port: 0, data: desc); }
