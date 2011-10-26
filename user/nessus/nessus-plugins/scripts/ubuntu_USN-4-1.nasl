# This script was automatically generated from the 4-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- glibc-doc 
- libc6 
- libc6-dbg 
- libc6-dev 
- libc6-i686 
- libc6-pic 
- libc6-prof 
- locales 
- nscd 


Description :

Recently, Trustix Secure Linux discovered some vulnerabilities in the
libc6 package. The utilities "catchsegv" and "glibcbug" created
temporary files in an insecure way, which allowed a symlink attack to
create or overwrite arbitrary files with the privileges of the user
invoking the program.

Solution :

Upgrade to : 
- glibc-doc-2.3.2.ds1-13ubuntu2.2 (Ubuntu 4.10)
- libc6-2.3.2.ds1-13ubuntu2.2 (Ubuntu 4.10)
- libc6-dbg-2.3.2.ds1-13ubuntu2.2 (Ubuntu 4.10)
- libc6-dev-2.3.2.ds1-13ubuntu2.2 (Ubuntu 4.10)
- libc6-i686-2.3.2.ds1-13ubuntu2.2 (Ubuntu 4.10)
- libc6-pic-2.3.2.ds1-13ubuntu2.2 (Ubuntu 4.10)
- libc6-prof-2.3.2.ds1-13ubuntu2.2 (Ubuntu 4.10)
- locales-2.3.2.ds1-13ubuntu2.2 (Ubuntu 4.10)
- nscd-2.3.2.ds1-13ubuntu2.2 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20656);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "4-1");
script_summary(english:"Standard C library script vulnerabilities");
script_name(english:"USN4-1 : Standard C library script vulnerabilities");
script_cve_id("CVE-2004-0968");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "glibc-doc", pkgver: "2.3.2.ds1-13ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package glibc-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to glibc-doc-2.3.2.ds1-13ubuntu2.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libc6", pkgver: "2.3.2.ds1-13ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libc6-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libc6-2.3.2.ds1-13ubuntu2.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libc6-dbg", pkgver: "2.3.2.ds1-13ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libc6-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libc6-dbg-2.3.2.ds1-13ubuntu2.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libc6-dev", pkgver: "2.3.2.ds1-13ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libc6-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libc6-dev-2.3.2.ds1-13ubuntu2.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libc6-i686", pkgver: "2.3.2.ds1-13ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libc6-i686-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libc6-i686-2.3.2.ds1-13ubuntu2.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libc6-pic", pkgver: "2.3.2.ds1-13ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libc6-pic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libc6-pic-2.3.2.ds1-13ubuntu2.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libc6-prof", pkgver: "2.3.2.ds1-13ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libc6-prof-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libc6-prof-2.3.2.ds1-13ubuntu2.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "locales", pkgver: "2.3.2.ds1-13ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package locales-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to locales-2.3.2.ds1-13ubuntu2.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "nscd", pkgver: "2.3.2.ds1-13ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package nscd-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to nscd-2.3.2.ds1-13ubuntu2.2
');
}

if (w) { security_hole(port: 0, data: desc); }
