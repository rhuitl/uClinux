# This script was automatically generated from the 74-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- postfix 
- postfix-dev 
- postfix-doc 
- postfix-ldap 
- postfix-mysql 
- postfix-pcre 
- postfix-pgsql 
- postfix-tls 


Description :

This is an update to the recently published Ubuntu Security Notice
USN-74-1, which fixed the delivery of arbitrary mail to any MX host
which has an IPv6 address.

Unfortunately that upgrade revealed an error in the package upgrade
system which caused package installation to fail. After the failed
upgrade the Postfix server was not started again, thus no mail was
delivered.

This new set of packages fixes the error encountered when upgrading.

Solution :

Upgrade to : 
- postfix-2.1.3-1ubuntu17.2 (Ubuntu 4.10)
- postfix-dev-2.1.3-1ubuntu17.2 (Ubuntu 4.10)
- postfix-doc-2.1.3-1ubuntu17.2 (Ubuntu 4.10)
- postfix-ldap-2.1.3-1ubuntu17.2 (Ubuntu 4.10)
- postfix-mysql-2.1.3-1ubuntu17.2 (Ubuntu 4.10)
- postfix-pcre-2.1.3-1ubuntu17.2 (Ubuntu 4.10)
- postfix-pgsql-2.1.3-1ubuntu17.2 (Ubuntu 4.10)
- postfix-tls-2.1.3-1ubuntu17.2 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20696);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "74-2");
script_summary(english:"postfix vulnerability");
script_name(english:"USN74-2 : postfix vulnerability");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "postfix", pkgver: "2.1.3-1ubuntu17.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postfix-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to postfix-2.1.3-1ubuntu17.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "postfix-dev", pkgver: "2.1.3-1ubuntu17.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postfix-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to postfix-dev-2.1.3-1ubuntu17.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "postfix-doc", pkgver: "2.1.3-1ubuntu17.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postfix-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to postfix-doc-2.1.3-1ubuntu17.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "postfix-ldap", pkgver: "2.1.3-1ubuntu17.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postfix-ldap-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to postfix-ldap-2.1.3-1ubuntu17.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "postfix-mysql", pkgver: "2.1.3-1ubuntu17.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postfix-mysql-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to postfix-mysql-2.1.3-1ubuntu17.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "postfix-pcre", pkgver: "2.1.3-1ubuntu17.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postfix-pcre-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to postfix-pcre-2.1.3-1ubuntu17.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "postfix-pgsql", pkgver: "2.1.3-1ubuntu17.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postfix-pgsql-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to postfix-pgsql-2.1.3-1ubuntu17.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "postfix-tls", pkgver: "2.1.3-1ubuntu17.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postfix-tls-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to postfix-tls-2.1.3-1ubuntu17.2
');
}

if (w) { security_hole(port: 0, data: desc); }
