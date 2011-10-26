# This script was automatically generated from the 204-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libssl-dev 
- libssl0.9.7 
- openssl 


Description :

Yutaka Oiwa discovered a possible cryptographic weakness in OpenSSL
applications. Applications using the OpenSSL library can use the
SSL_OP_MSIE_SSLV2_RSA_PADDING option (or SSL_OP_ALL, which implies the
former) to maintain compatibility with third party products, which is
achieved by working around known bugs in them.

The SSL_OP_MSIE_SSLV2_RSA_PADDING option disabled a verification step
in the SSL 2.0 server supposed to prevent active protocol-version
rollback attacks.  With this verification step disabled, an attacker
acting as a "man in the middle" could force a client and a server to
negotiate the SSL 2.0 protocol even if these parties both supported
SSL 3.0 or TLS 1.0.  The SSL 2.0 protocol is known to have severe
cryptographic weaknesses and is supported as a fallback only.

Solution :

Upgrade to : 
- libssl-dev-0.9.7g-1ubuntu1.1 (Ubuntu 5.10)
- libssl0.9.7-0.9.7g-1ubuntu1.1 (Ubuntu 5.10)
- openssl-0.9.7g-1ubuntu1.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(20620);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "204-1");
script_summary(english:"openssl vulnerability");
script_name(english:"USN204-1 : openssl vulnerability");
script_cve_id("CVE-2005-2969");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "libssl-dev", pkgver: "0.9.7g-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libssl-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libssl-dev-0.9.7g-1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libssl0.9.7", pkgver: "0.9.7g-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libssl0.9.7-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libssl0.9.7-0.9.7g-1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "openssl", pkgver: "0.9.7g-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openssl-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to openssl-0.9.7g-1ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
