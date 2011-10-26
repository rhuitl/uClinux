# This script was automatically generated from the 96-1 Ubuntu Security Notice
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

Stefano Di Paola discovered three privilege escalation flaws in the MySQL
server:

- If an authenticated user had INSERT privileges on the \'mysql\' administrative
  database, the CREATE FUNCTION command allowed that user to use libc functions
  to execute arbitrary code with the privileges of the database server (user
  \'mysql\'). (CVE-2005-0709)

- If an authenticated user had INSERT privileges on the \'mysql\' administrative
  database, it was possible to load a library located in an arbitrary directory
  by using INSERT INTO mysql.func instead of CREATE FUNCTION.  This allowed the
  user to execute arbitrary code with the privileges of the database server (user
  \'mysql\'). (CVE-2005-0710)

- Temporary files belonging to tables created with CREATE TEMPORARY TABLE were
  handled in an insecure way. This allowed any local computer user to overwrite
  arbitrary files with the privileges of the database server. (CVE-2005-0711)

Matt Brubeck discovered that the directory /usr/share/mysql/ was owned and
writ
[...]

Solution :

Upgrade to : 
- libmysqlclient-dev-4.0.20-2ubuntu1.4 (Ubuntu 4.10)
- libmysqlclient12-4.0.20-2ubuntu1.4 (Ubuntu 4.10)
- mysql-client-4.0.20-2ubuntu1.4 (Ubuntu 4.10)
- mysql-common-4.0.20-2ubuntu1.4 (Ubuntu 4.10)
- mysql-server-4.0.20-2ubuntu1.4 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20722);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "96-1");
script_summary(english:"mysql-dfsg vulnerabilities");
script_name(english:"USN96-1 : mysql-dfsg vulnerabilities");
script_cve_id("CVE-2005-0709","CVE-2005-0710","CVE-2005-0711");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "libmysqlclient-dev", pkgver: "4.0.20-2ubuntu1.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libmysqlclient-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libmysqlclient-dev-4.0.20-2ubuntu1.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libmysqlclient12", pkgver: "4.0.20-2ubuntu1.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libmysqlclient12-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libmysqlclient12-4.0.20-2ubuntu1.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mysql-client", pkgver: "4.0.20-2ubuntu1.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mysql-client-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mysql-client-4.0.20-2ubuntu1.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mysql-common", pkgver: "4.0.20-2ubuntu1.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mysql-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mysql-common-4.0.20-2ubuntu1.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mysql-server", pkgver: "4.0.20-2ubuntu1.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mysql-server-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mysql-server-4.0.20-2ubuntu1.4
');
}

if (w) { security_hole(port: 0, data: desc); }
