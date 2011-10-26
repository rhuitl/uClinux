# This script was automatically generated from the 283-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libmysqlclient12 
- libmysqlclient12-dev 
- libmysqlclient14 
- libmysqlclient14-dev 
- mysql-client 
- mysql-client-4.1 
- mysql-common 
- mysql-common-4.1 
- mysql-server 
- mysql-server-4.1 


Description :

Stefano Di Paola discovered an information leak in the login packet
parser. By sending a specially crafted malformed login packet, a
remote attacker could exploit this to read a random piece of memory,
which could potentially reveal sensitive data. (CVE-2006-1516)

Stefano Di Paola also found a similar information leak in the parser
for the COM_TABLE_DUMP request. (CVE-2006-1517)

Solution :

Upgrade to : 
- libmysqlclient12-4.0.24-10ubuntu2.2 (Ubuntu 5.10)
- libmysqlclient12-dev-4.0.24-10ubuntu2.2 (Ubuntu 5.10)
- libmysqlclient14-4.1.12-1ubuntu3.3 (Ubuntu 5.10)
- libmysqlclient14-dev-4.1.12-1ubuntu3.3 (Ubuntu 5.10)
- mysql-client-4.0.24-10ubuntu2.2 (Ubuntu 5.10)
- mysql-client-4.1-4.1.12-1ubuntu3.3 (Ubuntu 5.10)
- mysql-common-4.0.24-10ubuntu2.2 (Ubuntu 5.10)
- mysql-common-4.1-4.1.12-1ubuntu3.3 (Ubuntu 5.10)
- mysql-server-4.0.24-10ubuntu2.2 (Ubuntu 5.10)
- mysql-server-4.1-4.1.12-1ubuntu3.3 
[...]


Risk factor : High
';

if (description) {
script_id(21377);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "283-1");
script_summary(english:"mysql-dfsg-4.1, mysql-dfsg vulnerabilities");
script_name(english:"USN283-1 : mysql-dfsg-4.1, mysql-dfsg vulnerabilities");
script_cve_id("CVE-2006-1516","CVE-2006-1517");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "libmysqlclient12", pkgver: "4.0.24-10ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libmysqlclient12-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmysqlclient12-4.0.24-10ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmysqlclient12-dev", pkgver: "4.0.24-10ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libmysqlclient12-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmysqlclient12-dev-4.0.24-10ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmysqlclient14", pkgver: "4.1.12-1ubuntu3.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libmysqlclient14-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmysqlclient14-4.1.12-1ubuntu3.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmysqlclient14-dev", pkgver: "4.1.12-1ubuntu3.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libmysqlclient14-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmysqlclient14-dev-4.1.12-1ubuntu3.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mysql-client", pkgver: "4.0.24-10ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mysql-client-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mysql-client-4.0.24-10ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mysql-client-4.1", pkgver: "4.1.12-1ubuntu3.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mysql-client-4.1-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mysql-client-4.1-4.1.12-1ubuntu3.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mysql-common", pkgver: "4.0.24-10ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mysql-common-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mysql-common-4.0.24-10ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mysql-common-4.1", pkgver: "4.1.12-1ubuntu3.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mysql-common-4.1-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mysql-common-4.1-4.1.12-1ubuntu3.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mysql-server", pkgver: "4.0.24-10ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mysql-server-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mysql-server-4.0.24-10ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mysql-server-4.1", pkgver: "4.1.12-1ubuntu3.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mysql-server-4.1-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mysql-server-4.1-4.1.12-1ubuntu3.3
');
}

if (w) { security_hole(port: 0, data: desc); }
