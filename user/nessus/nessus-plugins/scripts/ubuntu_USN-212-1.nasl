# This script was automatically generated from the 212-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- gda2-freetds 
- gda2-mysql 
- gda2-odbc 
- gda2-postgres 
- gda2-sqlite 
- libgda2-1 
- libgda2-3 
- libgda2-3-dbg 
- libgda2-common 
- libgda2-dbg 
- libgda2-dev 
- libgda2-doc 


Description :

Steve Kemp discovered two format string vulnerabilities in the logging
handler of the Gnome database access library. Depending on the
application that uses the library, this could have been exploited to
execute arbitrary code with the permission of the user running the
application.

Solution :

Upgrade to : 
- gda2-freetds-1.2.1-2ubuntu3.1 (Ubuntu 5.10)
- gda2-mysql-1.2.1-2ubuntu3.1 (Ubuntu 5.10)
- gda2-odbc-1.2.1-2ubuntu3.1 (Ubuntu 5.10)
- gda2-postgres-1.2.1-2ubuntu3.1 (Ubuntu 5.10)
- gda2-sqlite-1.2.1-2ubuntu3.1 (Ubuntu 5.10)
- libgda2-1-1.1.99-1ubuntu0.1 (Ubuntu 5.04)
- libgda2-3-1.2.1-2ubuntu3.1 (Ubuntu 5.10)
- libgda2-3-dbg-1.2.1-2ubuntu3.1 (Ubuntu 5.10)
- libgda2-common-1.2.1-2ubuntu3.1 (Ubuntu 5.10)
- libgda2-dbg-1.1.99-1ubuntu0.1 (Ubuntu 5.04)
- libgda2-dev-1.2.1-2ubuntu3.1 (Ubuntu 5.10)
[...]


Risk factor : High
';

if (description) {
script_id(20630);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "212-1");
script_summary(english:"libgda2 vulnerability");
script_name(english:"USN212-1 : libgda2 vulnerability");
script_cve_id("CVE-2005-2958");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "gda2-freetds", pkgver: "1.2.1-2ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package gda2-freetds-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to gda2-freetds-1.2.1-2ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "gda2-mysql", pkgver: "1.2.1-2ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package gda2-mysql-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to gda2-mysql-1.2.1-2ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "gda2-odbc", pkgver: "1.2.1-2ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package gda2-odbc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to gda2-odbc-1.2.1-2ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "gda2-postgres", pkgver: "1.2.1-2ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package gda2-postgres-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to gda2-postgres-1.2.1-2ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "gda2-sqlite", pkgver: "1.2.1-2ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package gda2-sqlite-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to gda2-sqlite-1.2.1-2ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libgda2-1", pkgver: "1.1.99-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libgda2-1-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libgda2-1-1.1.99-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libgda2-3", pkgver: "1.2.1-2ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libgda2-3-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libgda2-3-1.2.1-2ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libgda2-3-dbg", pkgver: "1.2.1-2ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libgda2-3-dbg-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libgda2-3-dbg-1.2.1-2ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libgda2-common", pkgver: "1.2.1-2ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libgda2-common-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libgda2-common-1.2.1-2ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libgda2-dbg", pkgver: "1.1.99-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libgda2-dbg-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libgda2-dbg-1.1.99-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libgda2-dev", pkgver: "1.2.1-2ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libgda2-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libgda2-dev-1.2.1-2ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libgda2-doc", pkgver: "1.2.1-2ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libgda2-doc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libgda2-doc-1.2.1-2ubuntu3.1
');
}

if (w) { security_hole(port: 0, data: desc); }
