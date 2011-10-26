# This script was automatically generated from the 173-4 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- gnumeric 
- gnumeric-common 
- gnumeric-doc 
- gnumeric-plugins-extra 
- idle-python2.1 
- idle-python2.2 
- idle-python2.3 
- python2.1 
- python2.1-dev 
- python2.1-doc 
- python2.1-examples 
- python2.1-gdbm 
- python2.1-mpz 
- python2.1-tk 
- python2.1-xmlbase 
- python2.2 
- python2.2-dev 
- python2.2-doc 
- python2.2-examples 
- python2.2-gdbm 
- python2.2-mpz 
- python2.2-tk 
- python2.2-xmlbase 
- python2.3 
- python2.3-dev 
- python2.3-doc 
- 
[...]

Description :

USN-173-1 fixed a buffer overflow vulnerability in the PCRE library.
However, it was found that the various python packages and gnumeric
contain static copies of the library code, so these packages need to
be updated as well.

In gnumeric this bug could be exploited to execute arbitrary code with
the privileges of the user if the user was tricked into opening a
specially crafted spreadsheet document.

In python, the impact depends on the particular application that uses
python\'s "re" (regular expression) module. In python server
applications that process unchecked arbitrary regular expressions with
the "re" module, this could potentially be exploited to remotely
execute arbitrary code with the privileges of the server.

Solution :

Upgrade to : 
- gnumeric-1.4.2-1ubuntu3.1 (Ubuntu 5.04)
- gnumeric-common-1.4.2-1ubuntu3.1 (Ubuntu 5.04)
- gnumeric-doc-1.4.2-1ubuntu3.1 (Ubuntu 5.04)
- gnumeric-plugins-extra-1.4.2-1ubuntu3.1 (Ubuntu 5.04)
- idle-python2.1-2.1.3-24.ubuntu0.1 (Ubuntu 4.10)
- idle-python2.2-2.2.3dfsg-1ubuntu0.1 (Ubuntu 5.04)
- idle-python2.3-2.3.5-2ubuntu0.1 (Ubuntu 5.04)
- python2.1-2.1.3-24.ubuntu0.1 (Ubuntu 4.10)
- python2.1-dev-2.1.3-24.ubuntu0.1 (Ubuntu 4.10)
- python2.1-doc-2.1.3-24.ubuntu0.1 (Ubuntu 4.10)
- python2.1
[...]


Risk factor : High
';

if (description) {
script_id(20583);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "173-4");
script_summary(english:"python2.1, python2.2, python2.3, gnumeric vulnerabilities");
script_name(english:"USN173-4 : python2.1, python2.2, python2.3, gnumeric vulnerabilities");
script_cve_id("CVE-2005-2491");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "gnumeric", pkgver: "1.4.2-1ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package gnumeric-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to gnumeric-1.4.2-1ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "gnumeric-common", pkgver: "1.4.2-1ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package gnumeric-common-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to gnumeric-common-1.4.2-1ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "gnumeric-doc", pkgver: "1.4.2-1ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package gnumeric-doc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to gnumeric-doc-1.4.2-1ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "gnumeric-plugins-extra", pkgver: "1.4.2-1ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package gnumeric-plugins-extra-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to gnumeric-plugins-extra-1.4.2-1ubuntu3.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "idle-python2.1", pkgver: "2.1.3-24.ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package idle-python2.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to idle-python2.1-2.1.3-24.ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "idle-python2.2", pkgver: "2.2.3dfsg-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package idle-python2.2-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to idle-python2.2-2.2.3dfsg-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "idle-python2.3", pkgver: "2.3.5-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package idle-python2.3-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to idle-python2.3-2.3.5-2ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "python2.1", pkgver: "2.1.3-24.ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to python2.1-2.1.3-24.ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "python2.1-dev", pkgver: "2.1.3-24.ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.1-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to python2.1-dev-2.1.3-24.ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "python2.1-doc", pkgver: "2.1.3-24.ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.1-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to python2.1-doc-2.1.3-24.ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "python2.1-examples", pkgver: "2.1.3-24.ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.1-examples-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to python2.1-examples-2.1.3-24.ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "python2.1-gdbm", pkgver: "2.1.3-24.ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.1-gdbm-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to python2.1-gdbm-2.1.3-24.ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "python2.1-mpz", pkgver: "2.1.3-24.ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.1-mpz-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to python2.1-mpz-2.1.3-24.ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "python2.1-tk", pkgver: "2.1.3-24.ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.1-tk-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to python2.1-tk-2.1.3-24.ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "python2.1-xmlbase", pkgver: "2.1.3-24.ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.1-xmlbase-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to python2.1-xmlbase-2.1.3-24.ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "python2.2", pkgver: "2.2.3dfsg-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.2-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to python2.2-2.2.3dfsg-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "python2.2-dev", pkgver: "2.2.3dfsg-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.2-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to python2.2-dev-2.2.3dfsg-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "python2.2-doc", pkgver: "2.2.3dfsg-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.2-doc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to python2.2-doc-2.2.3dfsg-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "python2.2-examples", pkgver: "2.2.3dfsg-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.2-examples-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to python2.2-examples-2.2.3dfsg-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "python2.2-gdbm", pkgver: "2.2.3dfsg-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.2-gdbm-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to python2.2-gdbm-2.2.3dfsg-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "python2.2-mpz", pkgver: "2.2.3dfsg-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.2-mpz-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to python2.2-mpz-2.2.3dfsg-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "python2.2-tk", pkgver: "2.2.3dfsg-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.2-tk-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to python2.2-tk-2.2.3dfsg-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "python2.2-xmlbase", pkgver: "2.2.3dfsg-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.2-xmlbase-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to python2.2-xmlbase-2.2.3dfsg-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "python2.3", pkgver: "2.3.5-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.3-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to python2.3-2.3.5-2ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "python2.3-dev", pkgver: "2.3.5-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.3-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to python2.3-dev-2.3.5-2ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "python2.3-doc", pkgver: "2.3.5-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.3-doc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to python2.3-doc-2.3.5-2ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "python2.3-examples", pkgver: "2.3.5-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.3-examples-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to python2.3-examples-2.3.5-2ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "python2.3-gdbm", pkgver: "2.3.5-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.3-gdbm-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to python2.3-gdbm-2.3.5-2ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "python2.3-mpz", pkgver: "2.3.5-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.3-mpz-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to python2.3-mpz-2.3.5-2ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "python2.3-tk", pkgver: "2.3.5-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.3-tk-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to python2.3-tk-2.3.5-2ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
