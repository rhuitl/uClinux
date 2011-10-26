# This script was automatically generated from the 180-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libmysqlclient14 
- libmysqlclient14-dev 
- mysql-client-4.1 
- mysql-common-4.1 
- mysql-server-4.1 


Description :

USN-180-1 fixed a vulnerability in the mysql-server package (which
ships version 4.0). Version 4.1 is vulnerable against the same flaw.

Please note that this package is not officially supported in Ubuntu
5.10.

Origial advisory:

  "AppSecInc Team SHATTER discovered a buffer overflow in the "CREATE
  FUNCTION" statement. By specifying a specially crafted long function
  name, a local or remote attacker with function creation privileges
  could crash the server or execute arbitrary code with server
  privileges.

  However, the right to create function is usually not granted to
  untrusted users."

Solution :

Upgrade to : 
- libmysqlclient14-4.1.12-1ubuntu3.1 (Ubuntu 5.10)
- libmysqlclient14-dev-4.1.12-1ubuntu3.1 (Ubuntu 5.10)
- mysql-client-4.1-4.1.12-1ubuntu3.1 (Ubuntu 5.10)
- mysql-common-4.1-4.1.12-1ubuntu3.1 (Ubuntu 5.10)
- mysql-server-4.1-4.1.12-1ubuntu3.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(20760);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "180-2");
script_summary(english:"mysql-dfsg-4.1 vulnerability");
script_name(english:"USN180-2 : mysql-dfsg-4.1 vulnerability");
script_cve_id("CVE-2005-2558");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "libmysqlclient14", pkgver: "4.1.12-1ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libmysqlclient14-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmysqlclient14-4.1.12-1ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmysqlclient14-dev", pkgver: "4.1.12-1ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libmysqlclient14-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmysqlclient14-dev-4.1.12-1ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mysql-client-4.1", pkgver: "4.1.12-1ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mysql-client-4.1-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mysql-client-4.1-4.1.12-1ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mysql-common-4.1", pkgver: "4.1.12-1ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mysql-common-4.1-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mysql-common-4.1-4.1.12-1ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mysql-server-4.1", pkgver: "4.1.12-1ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mysql-server-4.1-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mysql-server-4.1-4.1.12-1ubuntu3.1
');
}

if (w) { security_hole(port: 0, data: desc); }
