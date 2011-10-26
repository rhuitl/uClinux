# This script was automatically generated from the 65-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- apache 
- apache-common 
- apache-dbg 
- apache-dev 
- apache-doc 
- apache-perl 
- apache-ssl 
- apache-utils 
- libapache-mod-perl 


Description :

Javier Fernández-Sanguino Peña noticed that the "check_forensic"
script created temporary files in an insecure manner. This could
allow a symbolic link attack to create or overwrite arbitrary files
with the privileges of the user invoking the program.

Solution :

Upgrade to : 
- apache-1.3.31-6ubuntu0.4 (Ubuntu 4.10)
- apache-common-1.3.31-6ubuntu0.4 (Ubuntu 4.10)
- apache-dbg-1.3.31-6ubuntu0.4 (Ubuntu 4.10)
- apache-dev-1.3.31-6ubuntu0.4 (Ubuntu 4.10)
- apache-doc-1.3.31-6ubuntu0.4 (Ubuntu 4.10)
- apache-perl-1.3.31-6ubuntu0.4 (Ubuntu 4.10)
- apache-ssl-1.3.31-6ubuntu0.4 (Ubuntu 4.10)
- apache-utils-1.3.31-6ubuntu0.4 (Ubuntu 4.10)
- libapache-mod-perl-1.29.0.2-14ubuntu0.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20684);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "65-1");
script_summary(english:"apache vulnerabilities");
script_name(english:"USN65-1 : apache vulnerabilities");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "apache", pkgver: "1.3.31-6ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache-1.3.31-6ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache-common", pkgver: "1.3.31-6ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache-common-1.3.31-6ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache-dbg", pkgver: "1.3.31-6ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache-dbg-1.3.31-6ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache-dev", pkgver: "1.3.31-6ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache-dev-1.3.31-6ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache-doc", pkgver: "1.3.31-6ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache-doc-1.3.31-6ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache-perl", pkgver: "1.3.31-6ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache-perl-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache-perl-1.3.31-6ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache-ssl", pkgver: "1.3.31-6ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache-ssl-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache-ssl-1.3.31-6ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache-utils", pkgver: "1.3.31-6ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package apache-utils-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache-utils-1.3.31-6ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libapache-mod-perl", pkgver: "1.29.0.2-14ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libapache-mod-perl-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libapache-mod-perl-1.29.0.2-14ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
