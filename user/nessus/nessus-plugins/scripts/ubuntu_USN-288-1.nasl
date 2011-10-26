# This script was automatically generated from the 288-1 Ubuntu Security Notice
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

CVE-2006-2313:
  Akio Ishida and Yasuo Ohgaki discovered a weakness in the handling of
  invalidly-encoded multibyte text data. If a client application
  processed untrusted input without respecting its encoding and applied
  standard string escaping techniques (such as replacing a single quote
  >>\'<< with >>\\\'<< or >>\'\'<<), the PostgreSQL server could interpret the
  resulting string in a way that allowed an attacker to inject arbitrary
  SQL commands into the resulting SQL query. The PostgreSQL server has
  been modified to reject such invalidly encoded strings now, which
  completely fixes the problem for some \'safe\' multibyte encodings like
  UTF-8.

CVE-2006-2314:
  However, there are some less popular and client-only multibyte
  encodings (such as SJIS, BIG5, GBK, GB18030, and UHC) which contain
  valid multibyte characters that end with the byte 0x5c, which is the
  representation of the backslash character >>\\<< in ASCII. Many client
  libraries and applications use the non-standard, but pop
[...]

Solution :

Upgrade to : 
- libecpg-compat2-8.0.3-15ubuntu2.2 (Ubuntu 5.10)
- libecpg-dev-8.0.3-15ubuntu2.2 (Ubuntu 5.10)
- libecpg4-7.4.7-2ubuntu2.3 (Ubuntu 5.04)
- libecpg5-8.0.3-15ubuntu2.2 (Ubuntu 5.10)
- libpgtcl-7.4.7-2ubuntu2.3 (Ubuntu 5.04)
- libpgtcl-dev-7.4.7-2ubuntu2.3 (Ubuntu 5.04)
- libpgtypes2-8.0.3-15ubuntu2.2 (Ubuntu 5.10)
- libpq-dev-8.0.3-15ubuntu2.2 (Ubuntu 5.10)
- libpq3-7.4.8-17ubuntu1.3 (Ubuntu 5.10)
- libpq4-8.0.3-15ubuntu2.2 (Ubuntu 5.10)
- postgresql-7.4.7-2ubuntu2.3 (Ubuntu 5.04)
- postgresql
[...]


Risk factor : High
';

if (description) {
script_id(21613);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "288-1");
script_summary(english:"postgresql-7.4/-8.0, postgresql, psycopg, ");
script_name(english:"USN288-1 : postgresql-7.4/-8.0, postgresql, psycopg, ");
script_cve_id("CVE-2006-2313","CVE-2006-2314");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "libecpg-compat2", pkgver: "8.0.3-15ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libecpg-compat2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libecpg-compat2-8.0.3-15ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libecpg-dev", pkgver: "8.0.3-15ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libecpg-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libecpg-dev-8.0.3-15ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libecpg4", pkgver: "7.4.7-2ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libecpg4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libecpg4-7.4.7-2ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libecpg5", pkgver: "8.0.3-15ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libecpg5-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libecpg5-8.0.3-15ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libpgtcl", pkgver: "7.4.7-2ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpgtcl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libpgtcl-7.4.7-2ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libpgtcl-dev", pkgver: "7.4.7-2ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpgtcl-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libpgtcl-dev-7.4.7-2ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libpgtypes2", pkgver: "8.0.3-15ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpgtypes2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libpgtypes2-8.0.3-15ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libpq-dev", pkgver: "8.0.3-15ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpq-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libpq-dev-8.0.3-15ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libpq3", pkgver: "7.4.8-17ubuntu1.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpq3-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libpq3-7.4.8-17ubuntu1.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libpq4", pkgver: "8.0.3-15ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpq4-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libpq4-8.0.3-15ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql", pkgver: "7.4.7-2ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-7.4.7-2ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-7.4", pkgver: "7.4.8-17ubuntu1.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-7.4-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-7.4-7.4.8-17ubuntu1.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-8.0", pkgver: "8.0.3-15ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-8.0-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-8.0-8.0.3-15ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-client", pkgver: "7.4.7-2ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-client-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-client-7.4.7-2ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-client-7.4", pkgver: "7.4.8-17ubuntu1.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-client-7.4-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-client-7.4-7.4.8-17ubuntu1.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-client-8.0", pkgver: "8.0.3-15ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-client-8.0-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-client-8.0-8.0.3-15ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-contrib", pkgver: "7.4.7-2ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-contrib-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-contrib-7.4.7-2ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-contrib-7.4", pkgver: "7.4.8-17ubuntu1.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-contrib-7.4-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-contrib-7.4-7.4.8-17ubuntu1.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-contrib-8.0", pkgver: "8.0.3-15ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-contrib-8.0-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-contrib-8.0-8.0.3-15ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-dev", pkgver: "7.4.7-2ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-dev-7.4.7-2ubuntu2.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-doc", pkgver: "7.4.7-2ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-doc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-doc-7.4.7-2ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-doc-7.4", pkgver: "7.4.8-17ubuntu1.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-doc-7.4-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-doc-7.4-7.4.8-17ubuntu1.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-doc-8.0", pkgver: "8.0.3-15ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-doc-8.0-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-doc-8.0-8.0.3-15ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-plperl-7.4", pkgver: "7.4.8-17ubuntu1.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-plperl-7.4-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-plperl-7.4-7.4.8-17ubuntu1.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-plperl-8.0", pkgver: "8.0.3-15ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-plperl-8.0-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-plperl-8.0-8.0.3-15ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-plpython-7.4", pkgver: "7.4.8-17ubuntu1.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-plpython-7.4-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-plpython-7.4-7.4.8-17ubuntu1.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-plpython-8.0", pkgver: "8.0.3-15ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-plpython-8.0-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-plpython-8.0-8.0.3-15ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-pltcl-7.4", pkgver: "7.4.8-17ubuntu1.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-pltcl-7.4-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-pltcl-7.4-7.4.8-17ubuntu1.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-pltcl-8.0", pkgver: "8.0.3-15ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-pltcl-8.0-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-pltcl-8.0-8.0.3-15ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-server-dev-7.4", pkgver: "7.4.8-17ubuntu1.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-server-dev-7.4-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-server-dev-7.4-7.4.8-17ubuntu1.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-server-dev-8.0", pkgver: "8.0.3-15ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-server-dev-8.0-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-server-dev-8.0-8.0.3-15ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "python-pgsql", pkgver: "2.4.0-6ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python-pgsql-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to python-pgsql-2.4.0-6ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "python-psycopg", pkgver: "1.1.18-1ubuntu6.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python-psycopg-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to python-psycopg-1.1.18-1ubuntu6.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "python2.3-pgsql", pkgver: "2.4.0-6ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.3-pgsql-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to python2.3-pgsql-2.4.0-6ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "python2.3-psycopg", pkgver: "1.1.18-1ubuntu6.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.3-psycopg-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to python2.3-psycopg-1.1.18-1ubuntu6.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "python2.4-pgsql", pkgver: "2.4.0-6ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.4-pgsql-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to python2.4-pgsql-2.4.0-6ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "python2.4-psycopg", pkgver: "1.1.18-1ubuntu6.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.4-psycopg-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to python2.4-psycopg-1.1.18-1ubuntu6.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "zope2.7-psycopgda", pkgver: "1.1.18-1ubuntu6.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package zope2.7-psycopgda-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to zope2.7-psycopgda-1.1.18-1ubuntu6.1
');
}

if (w) { security_hole(port: 0, data: desc); }
