# This script was automatically generated from the 79-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libecpg-dev 
- libecpg4 
- libpgtcl 
- libpgtcl-dev 
- libpq3 
- postgresql 
- postgresql-client 
- postgresql-contrib 
- postgresql-dev 
- postgresql-doc 


Description :

The execution of custom PostgreSQL functions can be restricted with
the EXECUTE privilege. However, previous versions did not check this
privilege when executing a function which was part of an aggregate.
As a result, any database user could circumvent the EXECUTE restriction of
functions with a particular (but very common) parameter structure by
creating an aggregate wrapper around the function. (CVE-2005-0244)

Several buffer overflows have been discovered in the SQL parser. These
could be exploited by any database user to crash the PostgreSQL server
or execute arbitrary code with the privileges of the server.
(CVE-2005-0245, CVE-2005-0247)

Finally, this update fixes a Denial of Service vulnerability of the
contributed "intagg" module. By constructing specially crafted arrays,
a database user was able to corrupt and crash the PostgreSQL server.
(CVE-2005-0246). Please note that this module is part of the
"postgresql-contrib" package, which is not officially supported by
Ubuntu.

Solution :

Upgrade to : 
- libecpg-dev-7.4.5-3ubuntu0.4 (Ubuntu 4.10)
- libecpg4-7.4.5-3ubuntu0.4 (Ubuntu 4.10)
- libpgtcl-7.4.5-3ubuntu0.4 (Ubuntu 4.10)
- libpgtcl-dev-7.4.5-3ubuntu0.4 (Ubuntu 4.10)
- libpq3-7.4.5-3ubuntu0.4 (Ubuntu 4.10)
- postgresql-7.4.5-3ubuntu0.4 (Ubuntu 4.10)
- postgresql-client-7.4.5-3ubuntu0.4 (Ubuntu 4.10)
- postgresql-contrib-7.4.5-3ubuntu0.4 (Ubuntu 4.10)
- postgresql-dev-7.4.5-3ubuntu0.4 (Ubuntu 4.10)
- postgresql-doc-7.4.5-3ubuntu0.4 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20702);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "79-1");
script_summary(english:"postgresql vulnerabilities");
script_name(english:"USN79-1 : postgresql vulnerabilities");
script_cve_id("CVE-2005-0244","CVE-2005-0245","CVE-2005-0246","CVE-2005-0247");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "libecpg-dev", pkgver: "7.4.5-3ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libecpg-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libecpg-dev-7.4.5-3ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libecpg4", pkgver: "7.4.5-3ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libecpg4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libecpg4-7.4.5-3ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libpgtcl", pkgver: "7.4.5-3ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpgtcl-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libpgtcl-7.4.5-3ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libpgtcl-dev", pkgver: "7.4.5-3ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpgtcl-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libpgtcl-dev-7.4.5-3ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libpq3", pkgver: "7.4.5-3ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpq3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libpq3-7.4.5-3ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "postgresql", pkgver: "7.4.5-3ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to postgresql-7.4.5-3ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "postgresql-client", pkgver: "7.4.5-3ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-client-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to postgresql-client-7.4.5-3ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "postgresql-contrib", pkgver: "7.4.5-3ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-contrib-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to postgresql-contrib-7.4.5-3ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "postgresql-dev", pkgver: "7.4.5-3ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to postgresql-dev-7.4.5-3ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "postgresql-doc", pkgver: "7.4.5-3ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package postgresql-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to postgresql-doc-7.4.5-3ubuntu0.4
');
}

if (w) { security_hole(port: 0, data: desc); }
