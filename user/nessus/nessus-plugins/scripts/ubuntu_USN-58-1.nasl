# This script was automatically generated from the 58-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- krb5-admin-server 
- krb5-clients 
- krb5-doc 
- krb5-ftpd 
- krb5-kdc 
- krb5-rsh-server 
- krb5-telnetd 
- krb5-user 
- libkadm55 
- libkrb5-dev 
- libkrb53 


Description :

Michael Tautschnig discovered a possible buffer overflow in the
add_to_history() function in the MIT Kerberos 5 implementation.
Performing a password change did not properly track the password
policy\'s history count and the maximum number of keys. This could
cause an array overflow and may have allowed authenticated users (not
necessarily one with administrative privileges) to execute arbitrary
code on the KDC host, compromising an entire Kerberos realm.

Solution :

Upgrade to : 
- krb5-admin-server-1.3.4-3ubuntu0.1 (Ubuntu 4.10)
- krb5-clients-1.3.4-3ubuntu0.1 (Ubuntu 4.10)
- krb5-doc-1.3.4-3ubuntu0.1 (Ubuntu 4.10)
- krb5-ftpd-1.3.4-3ubuntu0.1 (Ubuntu 4.10)
- krb5-kdc-1.3.4-3ubuntu0.1 (Ubuntu 4.10)
- krb5-rsh-server-1.3.4-3ubuntu0.1 (Ubuntu 4.10)
- krb5-telnetd-1.3.4-3ubuntu0.1 (Ubuntu 4.10)
- krb5-user-1.3.4-3ubuntu0.1 (Ubuntu 4.10)
- libkadm55-1.3.4-3ubuntu0.1 (Ubuntu 4.10)
- libkrb5-dev-1.3.4-3ubuntu0.1 (Ubuntu 4.10)
- libkrb53-1.3.4-3ubuntu0.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20676);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "58-1");
script_summary(english:"krb5 vulnerability");
script_name(english:"USN58-1 : krb5 vulnerability");
script_cve_id("CVE-2004-1189");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "krb5-admin-server", pkgver: "1.3.4-3ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package krb5-admin-server-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to krb5-admin-server-1.3.4-3ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "krb5-clients", pkgver: "1.3.4-3ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package krb5-clients-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to krb5-clients-1.3.4-3ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "krb5-doc", pkgver: "1.3.4-3ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package krb5-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to krb5-doc-1.3.4-3ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "krb5-ftpd", pkgver: "1.3.4-3ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package krb5-ftpd-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to krb5-ftpd-1.3.4-3ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "krb5-kdc", pkgver: "1.3.4-3ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package krb5-kdc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to krb5-kdc-1.3.4-3ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "krb5-rsh-server", pkgver: "1.3.4-3ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package krb5-rsh-server-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to krb5-rsh-server-1.3.4-3ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "krb5-telnetd", pkgver: "1.3.4-3ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package krb5-telnetd-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to krb5-telnetd-1.3.4-3ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "krb5-user", pkgver: "1.3.4-3ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package krb5-user-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to krb5-user-1.3.4-3ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libkadm55", pkgver: "1.3.4-3ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libkadm55-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libkadm55-1.3.4-3ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libkrb5-dev", pkgver: "1.3.4-3ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libkrb5-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libkrb5-dev-1.3.4-3ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libkrb53", pkgver: "1.3.4-3ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libkrb53-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libkrb53-1.3.4-3ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
