# This script was automatically generated from the 151-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- amd64-libs 
- amd64-libs-dev 
- dpkg 
- dpkg-dev 
- dpkg-doc 
- dselect 
- ia32-libs 
- ia32-libs-dev 


Description :

USN-148-1 and USN-151-1 fixed two security flaws in zlib, which could
be exploited to cause Denial of Service attacks or even arbitrary code
execution with malicious data streams.

Most applications use the shared library provided by the "zlib1g"
package; however, some packages contain copies of the affected zlib
code, so they need to be upgraded as well.

Solution :

Upgrade to : 
- amd64-libs-1.1ubuntu0.1 (Ubuntu 5.04)
- amd64-libs-dev-1.1ubuntu0.1 (Ubuntu 5.04)
- dpkg-1.10.27ubuntu1.1 (Ubuntu 5.04)
- dpkg-dev-1.10.27ubuntu1.1 (Ubuntu 5.04)
- dpkg-doc-1.10.27ubuntu1.1 (Ubuntu 5.04)
- dselect-1.10.27ubuntu1.1 (Ubuntu 5.04)
- ia32-libs-0.5ubuntu3.1 (Ubuntu 5.04)
- ia32-libs-dev-0.5ubuntu3.1 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20550);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "151-2");
script_summary(english:"dpkg, ia32-libs, amd64-libs vulnerabilities");
script_name(english:"USN151-2 : dpkg, ia32-libs, amd64-libs vulnerabilities");
script_cve_id("CVE-2005-1849","CVE-2005-2096");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "amd64-libs", pkgver: "1.1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package amd64-libs-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to amd64-libs-1.1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "amd64-libs-dev", pkgver: "1.1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package amd64-libs-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to amd64-libs-dev-1.1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "dpkg", pkgver: "1.10.27ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package dpkg-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to dpkg-1.10.27ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "dpkg-dev", pkgver: "1.10.27ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package dpkg-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to dpkg-dev-1.10.27ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "dpkg-doc", pkgver: "1.10.27ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package dpkg-doc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to dpkg-doc-1.10.27ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "dselect", pkgver: "1.10.27ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package dselect-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to dselect-1.10.27ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "ia32-libs", pkgver: "0.5ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package ia32-libs-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to ia32-libs-0.5ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "ia32-libs-dev", pkgver: "0.5ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package ia32-libs-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to ia32-libs-dev-0.5ubuntu3.1
');
}

if (w) { security_hole(port: 0, data: desc); }
