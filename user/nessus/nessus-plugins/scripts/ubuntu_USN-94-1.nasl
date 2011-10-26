# This script was automatically generated from the 94-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libcgi-fast-perl 
- libperl-dev 
- libperl5.8 
- perl 
- perl-base 
- perl-debug 
- perl-doc 
- perl-modules 
- perl-suid 


Description :

Paul Szabo discovered another vulnerability in the rmtree() function
in File::Path.pm. While a process running as root (or another user)
was busy deleting a directory tree, a different user could exploit a
race condition to create setuid binaries in this directory tree,
provided that he already had write permissions in any subdirectory of
that tree.

Solution :

Upgrade to : 
- libcgi-fast-perl-5.8.4-2ubuntu0.4 (Ubuntu 4.10)
- libperl-dev-5.8.4-2ubuntu0.4 (Ubuntu 4.10)
- libperl5.8-5.8.4-2ubuntu0.4 (Ubuntu 4.10)
- perl-5.8.4-2ubuntu0.4 (Ubuntu 4.10)
- perl-base-5.8.4-2ubuntu0.4 (Ubuntu 4.10)
- perl-debug-5.8.4-2ubuntu0.4 (Ubuntu 4.10)
- perl-doc-5.8.4-2ubuntu0.4 (Ubuntu 4.10)
- perl-modules-5.8.4-2ubuntu0.4 (Ubuntu 4.10)
- perl-suid-5.8.4-2ubuntu0.4 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20720);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "94-1");
script_summary(english:"perl vulnerability");
script_name(english:"USN94-1 : perl vulnerability");
script_cve_id("CVE-2005-0448");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "libcgi-fast-perl", pkgver: "5.8.4-2ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcgi-fast-perl-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcgi-fast-perl-5.8.4-2ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libperl-dev", pkgver: "5.8.4-2ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libperl-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libperl-dev-5.8.4-2ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libperl5.8", pkgver: "5.8.4-2ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libperl5.8-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libperl5.8-5.8.4-2ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "perl", pkgver: "5.8.4-2ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package perl-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to perl-5.8.4-2ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "perl-base", pkgver: "5.8.4-2ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package perl-base-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to perl-base-5.8.4-2ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "perl-debug", pkgver: "5.8.4-2ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package perl-debug-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to perl-debug-5.8.4-2ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "perl-doc", pkgver: "5.8.4-2ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package perl-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to perl-doc-5.8.4-2ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "perl-modules", pkgver: "5.8.4-2ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package perl-modules-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to perl-modules-5.8.4-2ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "perl-suid", pkgver: "5.8.4-2ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package perl-suid-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to perl-suid-5.8.4-2ubuntu0.4
');
}

if (w) { security_hole(port: 0, data: desc); }
