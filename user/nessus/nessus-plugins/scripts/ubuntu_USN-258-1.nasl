# This script was automatically generated from the 258-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libecpg-compat2 
- libecpg-dev 
- libecpg4 
- libecpg5 
- libpgtcl 
- libpgtcl-dev 
- libpgtypes2 
- libpq-dev 
- libpq3 
- libpq4 
- postgresql 
- postgresql-7.4 
- postgresql-8.0 
- postgresql-client 
- postgresql-client-7.4 
- postgresql-client-8.0 
- postgresql-contrib 
- postgresql-contrib-7.4 
- postgresql-contrib-8.0 
- postgresql-dev 
- postgresql-doc 
- postgresql-doc-7.4 
- postgresql-doc-8.0 
- postgresql-plperl-7.4 
- postgresql-plperl-8.0 
[...]

Description :

Akio Ishida discovered that the SET SESSION AUTHORIZATION command did
not properly verify the validity of its argument. An authenticated
PostgreSQL user could exploit this to crash the server.

However, this does not affect the official binary Ubuntu packages. The
crash can only be triggered if the source package is rebuilt with
assertions enabled (which is not the case in the official binary
packages).

Solution :

Upgrade to : 
- libecpg-compat2-8.0.3-15ubuntu2.1 (Ubuntu 5.04)
- libecpg-dev-8.0.3-15ubuntu2.1 (Ubuntu 5.04)
- libecpg4-7.4.7-2ubuntu2.2 (Ubuntu 5.04)
- libecpg5-8.0.3-15ubuntu2.1 (Ubuntu 5.04)
- libpgtcl-7.4.7-2ubuntu2.2 (Ubuntu 5.04)
- libpgtcl-dev-7.4.7-2ubuntu2.2 (Ubuntu 5.04)
- libpgtypes2-8.0.3-15ubuntu2.1 (Ubuntu 5.04)
- libpq-dev-8.0.3-15ubuntu2.1 (Ubuntu 5.04)
- libpq3-7.4.8-17ubuntu1.1 (Ubuntu 5.04)
- libpq4-8.0.3-15ubuntu2.1 (Ubuntu 5.04)
- postgresql-7.4.7-2ubuntu2.2 (Ubuntu 5.04)
- postgresql
[...]


Risk factor : High
';

if (description) {
script_id(21066);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "258-1");
script_summary(english:"postgresql-7.4, postgresql-8.0, postgresql vulnerability");
script_name(english:"USN258-1 : postgresql-7.4, postgresql-8.0, postgresql vulnerability");
script_cve_id("CVE-2006-0678");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "libecpg-compat2", pkgver: "8.0.3-15ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libecpg-compat2-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libecpg-compat2-8.0.3-15ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libecpg-dev", pkgver: "8.0.3-15ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libecpg-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libecpg-dev-8.0.3-15ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libecpg4", pkgver: "7.4.7-2ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libecpg4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libecpg4-7.4.7-2ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libecpg5", pkgver: "8.0.3-15ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libecpg5-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libecpg5-8.0.3-15ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libpgtcl", pkgver: "7.4.7-2ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpgtcl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libpgtcl-7.4.7-2ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libpgtcl-dev", pkgver: "7.4.7-2ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpgtcl-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libpgtcl-dev-7.4.7-2ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libpgtypes2", pkgver: "8.0.3-15ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpgtypes2-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libpgtypes2-8.0.3-15ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libpq-dev", pkgver: "8.0.3-15ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpq-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libpq-dev-8.0.3-15ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libpq3", pkgver: "7.4.8-17ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpq3-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libpq3-7.4.8-17ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libpq4", pkgver: "8.0.3-15ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpq4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libpq4-8.0.3-15ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql", pkgver: "7.4.7-2ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-7.4.7-2ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-7.4", pkgver: "7.4.8-17ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-7.4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-7.4-7.4.8-17ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-8.0", pkgver: "8.0.3-15ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-8.0-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-8.0-8.0.3-15ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-client", pkgver: "7.4.7-2ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-client-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-client-7.4.7-2ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-client-7.4", pkgver: "7.4.8-17ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-client-7.4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-client-7.4-7.4.8-17ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-client-8.0", pkgver: "8.0.3-15ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-client-8.0-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-client-8.0-8.0.3-15ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-contrib", pkgver: "7.4.7-2ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-contrib-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-contrib-7.4.7-2ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-contrib-7.4", pkgver: "7.4.8-17ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-contrib-7.4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-contrib-7.4-7.4.8-17ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-contrib-8.0", pkgver: "8.0.3-15ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-contrib-8.0-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-contrib-8.0-8.0.3-15ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-dev", pkgver: "7.4.7-2ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-dev-7.4.7-2ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-doc", pkgver: "7.4.7-2ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-doc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-doc-7.4.7-2ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-doc-7.4", pkgver: "7.4.8-17ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-doc-7.4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-doc-7.4-7.4.8-17ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-doc-8.0", pkgver: "8.0.3-15ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-doc-8.0-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-doc-8.0-8.0.3-15ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-plperl-7.4", pkgver: "7.4.8-17ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-plperl-7.4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-plperl-7.4-7.4.8-17ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-plperl-8.0", pkgver: "8.0.3-15ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-plperl-8.0-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-plperl-8.0-8.0.3-15ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-plpython-7.4", pkgver: "7.4.8-17ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-plpython-7.4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-plpython-7.4-7.4.8-17ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-plpython-8.0", pkgver: "8.0.3-15ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-plpython-8.0-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-plpython-8.0-8.0.3-15ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-pltcl-7.4", pkgver: "7.4.8-17ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-pltcl-7.4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-pltcl-7.4-7.4.8-17ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-pltcl-8.0", pkgver: "8.0.3-15ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-pltcl-8.0-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-pltcl-8.0-8.0.3-15ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-server-dev-7.4", pkgver: "7.4.8-17ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-server-dev-7.4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-server-dev-7.4-7.4.8-17ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-server-dev-8.0", pkgver: "8.0.3-15ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-server-dev-8.0-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-server-dev-8.0-8.0.3-15ubuntu2.1
');
}

if (w) { security_hole(port: 0, data: desc); }
