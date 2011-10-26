# This script was automatically generated from the 63-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libmysqlclient-dev 
- libmysqlclient12 
- mysql-client 
- mysql-common 
- mysql-server 


Description :

Javier Fernández-Sanguino Peña noticed that the "mysqlaccess" program
created temporary files in an insecure manner. This could allow a
symbolic link attack to create or overwrite arbitrary files with the
privileges of the user invoking the program.

Solution :

Upgrade to : 
- libmysqlclient-dev-4.0.20-2ubuntu1.2 (Ubuntu 4.10)
- libmysqlclient12-4.0.20-2ubuntu1.2 (Ubuntu 4.10)
- mysql-client-4.0.20-2ubuntu1.2 (Ubuntu 4.10)
- mysql-common-4.0.20-2ubuntu1.2 (Ubuntu 4.10)
- mysql-server-4.0.20-2ubuntu1.2 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20682);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "63-1");
script_summary(english:"mysql-dfsg vulnerability");
script_name(english:"USN63-1 : mysql-dfsg vulnerability");
script_cve_id("CVE-2005-0004");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "libmysqlclient-dev", pkgver: "4.0.20-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libmysqlclient-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libmysqlclient-dev-4.0.20-2ubuntu1.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libmysqlclient12", pkgver: "4.0.20-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libmysqlclient12-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libmysqlclient12-4.0.20-2ubuntu1.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mysql-client", pkgver: "4.0.20-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mysql-client-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mysql-client-4.0.20-2ubuntu1.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mysql-common", pkgver: "4.0.20-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mysql-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mysql-common-4.0.20-2ubuntu1.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mysql-server", pkgver: "4.0.20-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mysql-server-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mysql-server-4.0.20-2ubuntu1.2
');
}

if (w) { security_hole(port: 0, data: desc); }
