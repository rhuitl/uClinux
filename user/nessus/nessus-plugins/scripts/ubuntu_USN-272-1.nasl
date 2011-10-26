# This script was automatically generated from the 272-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libsasl2 
- libsasl2-dev 
- libsasl2-modules 
- libsasl2-modules-gssapi-heimdal 
- libsasl2-modules-kerberos-heimdal 
- libsasl2-modules-sql 
- sasl2-bin 


Description :

A Denial of Service vulnerability has been discovered in the SASL
authentication library when using the DIGEST-MD5 plugin. By sending a
specially crafted realm name, a malicious SASL server could exploit
this to crash the application that uses SASL.

Solution :

Upgrade to : 
- libsasl2-2.1.19-1.5ubuntu4.2 (Ubuntu 5.10)
- libsasl2-dev-2.1.19-1.5ubuntu4.2 (Ubuntu 5.10)
- libsasl2-modules-2.1.19-1.5ubuntu4.2 (Ubuntu 5.10)
- libsasl2-modules-gssapi-heimdal-2.1.19-1.5ubuntu4.2 (Ubuntu 5.10)
- libsasl2-modules-kerberos-heimdal-2.1.19-1.5ubuntu4.2 (Ubuntu 5.10)
- libsasl2-modules-sql-2.1.19-1.5ubuntu4.2 (Ubuntu 5.10)
- sasl2-bin-2.1.19-1.5ubuntu4.2 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(21291);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "272-1");
script_summary(english:"cyrus-sasl2 vulnerability");
script_name(english:"USN272-1 : cyrus-sasl2 vulnerability");
script_cve_id("CVE-2006-1721");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "libsasl2", pkgver: "2.1.19-1.5ubuntu4.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libsasl2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libsasl2-2.1.19-1.5ubuntu4.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libsasl2-dev", pkgver: "2.1.19-1.5ubuntu4.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libsasl2-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libsasl2-dev-2.1.19-1.5ubuntu4.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libsasl2-modules", pkgver: "2.1.19-1.5ubuntu4.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libsasl2-modules-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libsasl2-modules-2.1.19-1.5ubuntu4.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libsasl2-modules-gssapi-heimdal", pkgver: "2.1.19-1.5ubuntu4.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libsasl2-modules-gssapi-heimdal-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libsasl2-modules-gssapi-heimdal-2.1.19-1.5ubuntu4.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libsasl2-modules-kerberos-heimdal", pkgver: "2.1.19-1.5ubuntu4.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libsasl2-modules-kerberos-heimdal-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libsasl2-modules-kerberos-heimdal-2.1.19-1.5ubuntu4.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libsasl2-modules-sql", pkgver: "2.1.19-1.5ubuntu4.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libsasl2-modules-sql-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libsasl2-modules-sql-2.1.19-1.5ubuntu4.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "sasl2-bin", pkgver: "2.1.19-1.5ubuntu4.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package sasl2-bin-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to sasl2-bin-2.1.19-1.5ubuntu4.2
');
}

if (w) { security_hole(port: 0, data: desc); }
