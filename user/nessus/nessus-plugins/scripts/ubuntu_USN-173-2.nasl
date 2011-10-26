# This script was automatically generated from the 173-2 Ubuntu Security Notice
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
- libapr0 
- libapr0-dev 
- libpcre3 
- libpcre3-dev 
- pcregrep 
- pgrep 


Description :

USN-173-1 fixed a buffer overflow vulnerability in the PCRE library.
However, it was determined that this did not suffice to prevent all
possible overflows, so another update is necessary.

In addition, it was found that the Ubuntu 4.10 version of Apache 2
contains a static copy of the library code, so this package needs to
be updated as well. In Ubuntu 5.04, Apache 2 uses the external library
from the libpcre3 package.

Solution :

Upgrade to : 
- apache2-2.0.50-12ubuntu4.4 (Ubuntu 4.10)
- apache2-common-2.0.50-12ubuntu4.4 (Ubuntu 4.10)
- apache2-doc-2.0.50-12ubuntu4.4 (Ubuntu 4.10)
- apache2-mpm-perchild-2.0.50-12ubuntu4.4 (Ubuntu 4.10)
- apache2-mpm-prefork-2.0.50-12ubuntu4.4 (Ubuntu 4.10)
- apache2-mpm-threadpool-2.0.50-12ubuntu4.4 (Ubuntu 4.10)
- apache2-mpm-worker-2.0.50-12ubuntu4.4 (Ubuntu 4.10)
- apache2-prefork-dev-2.0.50-12ubuntu4.4 (Ubuntu 4.10)
- apache2-threaded-dev-2.0.50-12ubuntu4.4 (Ubuntu 4.10)
- libapr0-2.0.50-12ubun
[...]


Risk factor : High
';

if (description) {
script_id(20581);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "173-2");
script_summary(english:"pcre3, apache2 vulnerabilities");
script_name(english:"USN173-2 : pcre3, apache2 vulnerabilities");
script_cve_id("CVE-2005-2491");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "apache2", pkgver: "2.0.50-12ubuntu4.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache2-2.0.50-12ubuntu4.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache2-common", pkgver: "2.0.50-12ubuntu4.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache2-common-2.0.50-12ubuntu4.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache2-doc", pkgver: "2.0.50-12ubuntu4.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache2-doc-2.0.50-12ubuntu4.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache2-mpm-perchild", pkgver: "2.0.50-12ubuntu4.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-mpm-perchild-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache2-mpm-perchild-2.0.50-12ubuntu4.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache2-mpm-prefork", pkgver: "2.0.50-12ubuntu4.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-mpm-prefork-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache2-mpm-prefork-2.0.50-12ubuntu4.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache2-mpm-threadpool", pkgver: "2.0.50-12ubuntu4.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-mpm-threadpool-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache2-mpm-threadpool-2.0.50-12ubuntu4.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache2-mpm-worker", pkgver: "2.0.50-12ubuntu4.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-mpm-worker-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache2-mpm-worker-2.0.50-12ubuntu4.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache2-prefork-dev", pkgver: "2.0.50-12ubuntu4.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-prefork-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache2-prefork-dev-2.0.50-12ubuntu4.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache2-threaded-dev", pkgver: "2.0.50-12ubuntu4.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache2-threaded-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache2-threaded-dev-2.0.50-12ubuntu4.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libapr0", pkgver: "2.0.50-12ubuntu4.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libapr0-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libapr0-2.0.50-12ubuntu4.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libapr0-dev", pkgver: "2.0.50-12ubuntu4.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libapr0-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libapr0-dev-2.0.50-12ubuntu4.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libpcre3", pkgver: "4.5-1.1ubuntu0.5.04.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpcre3-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libpcre3-4.5-1.1ubuntu0.5.04.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libpcre3-dev", pkgver: "4.5-1.1ubuntu0.5.04.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpcre3-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libpcre3-dev-4.5-1.1ubuntu0.5.04.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "pcregrep", pkgver: "4.5-1.1ubuntu0.5.04.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package pcregrep-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to pcregrep-4.5-1.1ubuntu0.5.04.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "pgrep", pkgver: "4.5-1.1ubuntu0.5.04.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package pgrep-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to pgrep-4.5-1.1ubuntu0.5.04.1
');
}

if (w) { security_hole(port: 0, data: desc); }
