# This script was automatically generated from the 73-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- idle-python2.2 
- idle-python2.3 
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
- python2.3-examples 
- python2.3-gdbm 
- python2.3-mpz 
- python2.3-tk 


Description :

The Python developers discovered a flaw in the SimpleXMLRPCServer
module. Python XML-RPC servers that used the register_instance()
method to register an object, but do not have a _dispatch() method,
allowed remote users to access or change function internals using the
im_* and func_* attributes.

Solution :

Upgrade to : 
- idle-python2.2-2.2.3-10ubuntu0.1 (Ubuntu 4.10)
- idle-python2.3-2.3.4-2ubuntu0.1 (Ubuntu 4.10)
- python2.2-2.2.3-10ubuntu0.1 (Ubuntu 4.10)
- python2.2-dev-2.2.3-10ubuntu0.1 (Ubuntu 4.10)
- python2.2-doc-2.2.3-10ubuntu0.1 (Ubuntu 4.10)
- python2.2-examples-2.2.3-10ubuntu0.1 (Ubuntu 4.10)
- python2.2-gdbm-2.2.3-10ubuntu0.1 (Ubuntu 4.10)
- python2.2-mpz-2.2.3-10ubuntu0.1 (Ubuntu 4.10)
- python2.2-tk-2.2.3-10ubuntu0.1 (Ubuntu 4.10)
- python2.2-xmlbase-2.2.3-10ubuntu0.1 (Ubuntu 4.10)
- python2.3
[...]


Risk factor : High
';

if (description) {
script_id(20694);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "73-1");
script_summary(english:"python2.2, python2.3 vulnerability");
script_name(english:"USN73-1 : python2.2, python2.3 vulnerability");
script_cve_id("CVE-2005-0089");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "idle-python2.2", pkgver: "2.2.3-10ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package idle-python2.2-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to idle-python2.2-2.2.3-10ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "idle-python2.3", pkgver: "2.3.4-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package idle-python2.3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to idle-python2.3-2.3.4-2ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "python2.2", pkgver: "2.2.3-10ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.2-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to python2.2-2.2.3-10ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "python2.2-dev", pkgver: "2.2.3-10ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.2-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to python2.2-dev-2.2.3-10ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "python2.2-doc", pkgver: "2.2.3-10ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.2-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to python2.2-doc-2.2.3-10ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "python2.2-examples", pkgver: "2.2.3-10ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.2-examples-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to python2.2-examples-2.2.3-10ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "python2.2-gdbm", pkgver: "2.2.3-10ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.2-gdbm-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to python2.2-gdbm-2.2.3-10ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "python2.2-mpz", pkgver: "2.2.3-10ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.2-mpz-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to python2.2-mpz-2.2.3-10ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "python2.2-tk", pkgver: "2.2.3-10ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.2-tk-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to python2.2-tk-2.2.3-10ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "python2.2-xmlbase", pkgver: "2.2.3-10ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.2-xmlbase-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to python2.2-xmlbase-2.2.3-10ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "python2.3", pkgver: "2.3.4-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to python2.3-2.3.4-2ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "python2.3-dev", pkgver: "2.3.4-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.3-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to python2.3-dev-2.3.4-2ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "python2.3-doc", pkgver: "2.3.4-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.3-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to python2.3-doc-2.3.4-2ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "python2.3-examples", pkgver: "2.3.4-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.3-examples-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to python2.3-examples-2.3.4-2ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "python2.3-gdbm", pkgver: "2.3.4-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.3-gdbm-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to python2.3-gdbm-2.3.4-2ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "python2.3-mpz", pkgver: "2.3.4-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.3-mpz-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to python2.3-mpz-2.3.4-2ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "python2.3-tk", pkgver: "2.3.4-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.3-tk-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to python2.3-tk-2.3.4-2ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
