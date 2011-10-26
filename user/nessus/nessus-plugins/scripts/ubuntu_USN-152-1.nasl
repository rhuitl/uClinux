# This script was automatically generated from the 152-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- ldap-utils 
- libldap2 
- libldap2-dev 
- libnss-ldap 
- libpam-ldap 
- libslapd2-dev 
- slapd 


Description :

Andrea Barisani discovered a flaw in the SSL handling of pam-ldap and
libnss-ldap. When a client connected to a slave LDAP server using SSL,
the slave server did not use SSL as well when contacting the LDAP
master server. This caused passwords and other confident information
to be transmitted unencrypted between the slave and the master.

Solution :

Upgrade to : 
- ldap-utils-2.1.30-3ubuntu3.1 (Ubuntu 5.04)
- libldap2-2.1.30-3ubuntu3.1 (Ubuntu 5.04)
- libldap2-dev-2.1.30-3ubuntu3.1 (Ubuntu 5.04)
- libnss-ldap-220-1ubuntu0.1 (Ubuntu 5.04)
- libpam-ldap-169-1ubuntu0.1 (Ubuntu 5.04)
- libslapd2-dev-2.1.30-3ubuntu3.1 (Ubuntu 5.04)
- slapd-2.1.30-3ubuntu3.1 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20553);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "152-1");
script_summary(english:"openldap2, libpam-ldap, libnss-ldap vulnerabilities");
script_name(english:"USN152-1 : openldap2, libpam-ldap, libnss-ldap vulnerabilities");
script_cve_id("CVE-2005-2069");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "ldap-utils", pkgver: "2.1.30-3ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package ldap-utils-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to ldap-utils-2.1.30-3ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libldap2", pkgver: "2.1.30-3ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libldap2-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libldap2-2.1.30-3ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libldap2-dev", pkgver: "2.1.30-3ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libldap2-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libldap2-dev-2.1.30-3ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libnss-ldap", pkgver: "220-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libnss-ldap-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libnss-ldap-220-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libpam-ldap", pkgver: "169-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpam-ldap-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libpam-ldap-169-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libslapd2-dev", pkgver: "2.1.30-3ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libslapd2-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libslapd2-dev-2.1.30-3ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "slapd", pkgver: "2.1.30-3ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package slapd-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to slapd-2.1.30-3ubuntu3.1
');
}

if (w) { security_hole(port: 0, data: desc); }
