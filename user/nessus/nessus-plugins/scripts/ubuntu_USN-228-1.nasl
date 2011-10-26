# This script was automatically generated from the 228-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- curl 
- libcurl2 
- libcurl2-dbg 
- libcurl2-dev 
- libcurl2-gssapi 
- libcurl3 
- libcurl3-dbg 
- libcurl3-dev 
- libcurl3-gssapi 


Description :

Stefan Esser discovered several buffer overflows in the handling of
URLs. By attempting to load an URL with a specially crafted invalid
hostname, a local attacker could exploit this to execute arbitrary
code with the privileges of the application that uses the cURL
library.

It is not possible to trick cURL into loading a malicious URL with an
HTTP redirect, so this vulnerability was usually not exploitable
remotely. However, it could be exploited locally to e. g. circumvent
PHP security restrictions.

Solution :

Upgrade to : 
- curl-7.14.0-2ubuntu1.2 (Ubuntu 5.10)
- libcurl2-7.11.2-12ubuntu3.3 (Ubuntu 5.04)
- libcurl2-dbg-7.12.0.is.7.11.2-1ubuntu0.3 (Ubuntu 4.10)
- libcurl2-dev-7.11.2-12ubuntu3.3 (Ubuntu 5.04)
- libcurl2-gssapi-7.12.0.is.7.11.2-1ubuntu0.3 (Ubuntu 4.10)
- libcurl3-7.14.0-2ubuntu1.2 (Ubuntu 5.10)
- libcurl3-dbg-7.14.0-2ubuntu1.2 (Ubuntu 5.10)
- libcurl3-dev-7.14.0-2ubuntu1.2 (Ubuntu 5.10)
- libcurl3-gssapi-7.14.0-2ubuntu1.2 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(20771);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "228-1");
script_summary(english:"curl vulnerability");
script_name(english:"USN228-1 : curl vulnerability");
script_cve_id("CVE-2005-4077");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "curl", pkgver: "7.14.0-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package curl-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to curl-7.14.0-2ubuntu1.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libcurl2", pkgver: "7.11.2-12ubuntu3.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcurl2-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libcurl2-7.11.2-12ubuntu3.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcurl2-dbg", pkgver: "7.12.0.is.7.11.2-1ubuntu0.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcurl2-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcurl2-dbg-7.12.0.is.7.11.2-1ubuntu0.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libcurl2-dev", pkgver: "7.11.2-12ubuntu3.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcurl2-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libcurl2-dev-7.11.2-12ubuntu3.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcurl2-gssapi", pkgver: "7.12.0.is.7.11.2-1ubuntu0.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcurl2-gssapi-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcurl2-gssapi-7.12.0.is.7.11.2-1ubuntu0.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libcurl3", pkgver: "7.14.0-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcurl3-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libcurl3-7.14.0-2ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libcurl3-dbg", pkgver: "7.14.0-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcurl3-dbg-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libcurl3-dbg-7.14.0-2ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libcurl3-dev", pkgver: "7.14.0-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcurl3-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libcurl3-dev-7.14.0-2ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libcurl3-gssapi", pkgver: "7.14.0-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcurl3-gssapi-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libcurl3-gssapi-7.14.0-2ubuntu1.2
');
}

if (w) { security_hole(port: 0, data: desc); }
