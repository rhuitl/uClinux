# This script was automatically generated from the 86-1 Ubuntu Security Notice
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


Description :

infamous41md discovered a buffer overflow in cURL\'s NT LAN Manager
(NTLM) authentication handling. By sending a specially crafted long
NTLM reply packet, a remote attacker could overflow the reply buffer.
This could lead to execution of arbitrary attacker specified code with
the privileges of the application using the cURL library.

Solution :

Upgrade to : 
- curl-7.12.0.is.7.11.2-1ubuntu0.1 (Ubuntu 4.10)
- libcurl2-7.12.0.is.7.11.2-1ubuntu0.1 (Ubuntu 4.10)
- libcurl2-dbg-7.12.0.is.7.11.2-1ubuntu0.1 (Ubuntu 4.10)
- libcurl2-dev-7.12.0.is.7.11.2-1ubuntu0.1 (Ubuntu 4.10)
- libcurl2-gssapi-7.12.0.is.7.11.2-1ubuntu0.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20711);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "86-1");
script_summary(english:"curl vulnerability");
script_name(english:"USN86-1 : curl vulnerability");
script_cve_id("CVE-2005-0940");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "curl", pkgver: "7.12.0.is.7.11.2-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package curl-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to curl-7.12.0.is.7.11.2-1ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcurl2", pkgver: "7.12.0.is.7.11.2-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcurl2-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcurl2-7.12.0.is.7.11.2-1ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcurl2-dbg", pkgver: "7.12.0.is.7.11.2-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcurl2-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcurl2-dbg-7.12.0.is.7.11.2-1ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcurl2-dev", pkgver: "7.12.0.is.7.11.2-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcurl2-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcurl2-dev-7.12.0.is.7.11.2-1ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcurl2-gssapi", pkgver: "7.12.0.is.7.11.2-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcurl2-gssapi-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcurl2-gssapi-7.12.0.is.7.11.2-1ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
