# This script was automatically generated from the 241-1 Ubuntu Security Notice
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
- libapache-mod-perl 
- libapr0 
- libapr0-dev 


Description :

The "mod_imap" module (which provides support for image maps) did not
properly escape the "referer" URL which rendered it vulnerable against
a cross-site scripting attack. A malicious web page (or HTML email)
could trick a user into visiting a site running the vulnerable mod_imap,
and employ cross-site-scripting techniques to gather sensitive user
information from that site. (CVE-2005-3352)

Hartmut Keil discovered a Denial of Service vulnerability in the SSL
module ("mod_ssl") that affects SSL-enabled virtual hosts with a
customized error page for error 400. By sending a specially crafted
request to the server, a remote attacker could crash the server. This
only affects Apache 2, and only if the "worker" implementation
(apache2-mpm-worker) is used. (CVE-2005-3357)

Solution :

Upgrade to : 
- apache-1.3.33-8ubuntu1 (Ubuntu 5.10)
- apache-common-1.3.33-8ubuntu1 (Ubuntu 5.10)
- apache-dbg-1.3.33-8ubuntu1 (Ubuntu 5.10)
- apache-dev-1.3.33-8ubuntu1 (Ubuntu 5.10)
- apache-doc-1.3.33-8ubuntu1 (Ubuntu 5.10)
- apache-perl-1.3.33-8ubuntu1 (Ubuntu 5.10)
- apache-ssl-1.3.33-8ubuntu1 (Ubuntu 5.10)
- apache-utils-1.3.33-8ubuntu1 (Ubuntu 5.10)
- apache2-2.0.54-5ubuntu4 (Ubuntu 5.10)
- apache2-common-2.0.54-5ubuntu4 (Ubuntu 5.10)
- apache2-doc-2.0.54-5ubuntu4 (Ubuntu 5.10)
- apache2-mpm-perchi
[...]


Risk factor : High
';

if (description) {
script_id(20788);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "241-1");
script_summary(english:"apache2, apache vulnerabilities");
script_name(english:"USN241-1 : apache2, apache vulnerabilities");
script_cve_id("CVE-2005-3352","CVE-2005-3357");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "apache", pkgver: "1.3.33-8ubuntu1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to apache-1.3.33-8ubuntu1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "apache-common", pkgver: "1.3.33-8ubuntu1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache-common-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to apache-common-1.3.33-8ubuntu1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "apache-dbg", pkgver: "1.3.33-8ubuntu1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache-dbg-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to apache-dbg-1.3.33-8ubuntu1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "apache-dev", pkgver: "1.3.33-8ubuntu1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to apache-dev-1.3.33-8ubuntu1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "apache-doc", pkgver: "1.3.33-8ubuntu1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache-doc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to apache-doc-1.3.33-8ubuntu1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "apache-perl", pkgver: "1.3.33-8ubuntu1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache-perl-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to apache-perl-1.3.33-8ubuntu1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "apache-ssl", pkgver: "1.3.33-8ubuntu1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache-ssl-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to apache-ssl-1.3.33-8ubuntu1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "apache-utils", pkgver: "1.3.33-8ubuntu1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache-utils-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to apache-utils-1.3.33-8ubuntu1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "apache2", pkgver: "2.0.54-5ubuntu4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to apache2-2.0.54-5ubuntu4
');
}
found = ubuntu_check(osver: "5.10", pkgname: "apache2-common", pkgver: "2.0.54-5ubuntu4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-common-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to apache2-common-2.0.54-5ubuntu4
');
}
found = ubuntu_check(osver: "5.10", pkgname: "apache2-doc", pkgver: "2.0.54-5ubuntu4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-doc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to apache2-doc-2.0.54-5ubuntu4
');
}
found = ubuntu_check(osver: "5.10", pkgname: "apache2-mpm-perchild", pkgver: "2.0.54-5ubuntu4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-mpm-perchild-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to apache2-mpm-perchild-2.0.54-5ubuntu4
');
}
found = ubuntu_check(osver: "5.10", pkgname: "apache2-mpm-prefork", pkgver: "2.0.54-5ubuntu4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-mpm-prefork-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to apache2-mpm-prefork-2.0.54-5ubuntu4
');
}
found = ubuntu_check(osver: "5.10", pkgname: "apache2-mpm-threadpool", pkgver: "2.0.54-5ubuntu4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-mpm-threadpool-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to apache2-mpm-threadpool-2.0.54-5ubuntu4
');
}
found = ubuntu_check(osver: "5.10", pkgname: "apache2-mpm-worker", pkgver: "2.0.54-5ubuntu4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-mpm-worker-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to apache2-mpm-worker-2.0.54-5ubuntu4
');
}
found = ubuntu_check(osver: "5.10", pkgname: "apache2-prefork-dev", pkgver: "2.0.54-5ubuntu4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-prefork-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to apache2-prefork-dev-2.0.54-5ubuntu4
');
}
found = ubuntu_check(osver: "5.10", pkgname: "apache2-threaded-dev", pkgver: "2.0.54-5ubuntu4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-threaded-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to apache2-threaded-dev-2.0.54-5ubuntu4
');
}
found = ubuntu_check(osver: "5.10", pkgname: "apache2-utils", pkgver: "2.0.54-5ubuntu4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-utils-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to apache2-utils-2.0.54-5ubuntu4
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libapache-mod-perl", pkgver: "1.29.0.3-8ubuntu1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libapache-mod-perl-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libapache-mod-perl-1.29.0.3-8ubuntu1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libapr0", pkgver: "2.0.54-5ubuntu4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libapr0-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libapr0-2.0.54-5ubuntu4
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libapr0-dev", pkgver: "2.0.54-5ubuntu4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libapr0-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libapr0-dev-2.0.54-5ubuntu4
');
}

if (w) { security_hole(port: 0, data: desc); }
