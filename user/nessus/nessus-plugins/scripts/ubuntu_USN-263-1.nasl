# This script was automatically generated from the 263-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- linux-doc-2.6.10 
- linux-doc-2.6.12 
- linux-doc-2.6.8.1 
- linux-headers-2.6.10-6 
- linux-headers-2.6.10-6-386 
- linux-headers-2.6.10-6-686 
- linux-headers-2.6.10-6-686-smp 
- linux-headers-2.6.10-6-amd64-generic 
- linux-headers-2.6.10-6-amd64-k8 
- linux-headers-2.6.10-6-amd64-k8-smp 
- linux-headers-2.6.10-6-amd64-xeon 
- linux-headers-2.6.10-6-k7 
- linux-headers-2.6.10-6-k7-smp 
- linux-headers-2.6.10-6-power3 
- linux-headers-2.6.10-6-power3
[...]

Description :

A flaw was found in the module reference counting for loadable
protocol modules of netfilter. By performing particular socket
operations, a local attacker could exploit this to crash the kernel.
This flaw only affects Ubuntu 5.10. (CVE-2005-3359)

David Howells noticed a race condition in the add_key(), request_key()
and keyctl() functions. By modifying the length of string arguments
after the kernel determined their length, but before the kernel copied
them into kernel memory, a local attacker could either crash the
kernel or read random parts of kernel memory (which could potentially
contain sensitive data). (CVE-2006-0457)

An information disclosure vulnerability was discovered in the
ftruncate() function for the XFS file system. Under certain
conditions, this function could expose random unallocated blocks.
A local user could potentially exploit this to recover sensitive data
from previously deleted files. (CVE-2006-0554)

A local Denial of Service vulnerability was found in the NFS client
module. By ope
[...]

Solution :

Upgrade to : 
- linux-doc-2.6.10-2.6.10-34.12 (Ubuntu 5.04)
- linux-doc-2.6.12-2.6.12-10.30 (Ubuntu 5.10)
- linux-doc-2.6.8.1-2.6.8.1-16.28 (Ubuntu 4.10)
- linux-headers-2.6.10-6-2.6.10-34.12 (Ubuntu 5.04)
- linux-headers-2.6.10-6-386-2.6.10-34.12 (Ubuntu 5.04)
- linux-headers-2.6.10-6-686-2.6.10-34.12 (Ubuntu 5.04)
- linux-headers-2.6.10-6-686-smp-2.6.10-34.12 (Ubuntu 5.04)
- linux-headers-2.6.10-6-amd64-generic-2.6.10-34.12 (Ubuntu 5.04)
- linux-headers-2.6.10-6-amd64-k8-2.6.10-34.12 (Ubuntu 5.04)
- linu
[...]


Risk factor : High
';

if (description) {
script_id(21070);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "263-1");
script_summary(english:"linux-source-2.6.8.1/-2.6.10/-2.6.12 vulnerabilities");
script_name(english:"USN263-1 : linux-source-2.6.8.1/-2.6.10/-2.6.12 vulnerabilities");
script_cve_id("CVE-2005-3359","CVE-2006-0457","CVE-2006-0554","CVE-2006-0555","CVE-2006-0741","CVE-2006-0742");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "linux-doc-2.6.10", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-doc-2.6.10-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-doc-2.6.10-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-doc-2.6.12", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-doc-2.6.12-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-doc-2.6.12-2.6.12-10.30
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-doc-2.6.8.1", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-doc-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-doc-2.6.8.1-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-386", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-386-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-386-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-686", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-686-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-686-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-686-smp", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-686-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-686-smp-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-amd64-generic", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-amd64-generic-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-amd64-generic-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-amd64-k8", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-amd64-k8-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-amd64-k8-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-amd64-k8-smp", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-amd64-k8-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-amd64-k8-smp-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-amd64-xeon", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-amd64-xeon-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-amd64-xeon-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-k7", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-k7-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-k7-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-k7-smp", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-k7-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-k7-smp-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-power3", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-power3-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-power3-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-power3-smp", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-power3-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-power3-smp-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-power4", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-power4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-power4-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-power4-smp", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-power4-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-power4-smp-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-powerpc", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-powerpc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-powerpc-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-powerpc-smp", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-powerpc-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-powerpc-smp-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-2.6.12-10.30
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-386", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-386-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-386-2.6.12-10.30
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-686", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-686-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-686-2.6.12-10.30
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-686-smp", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-686-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-686-smp-2.6.12-10.30
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-amd64-generic", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-amd64-generic-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-amd64-generic-2.6.12-10.30
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-amd64-k8", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-amd64-k8-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-amd64-k8-2.6.12-10.30
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-amd64-k8-smp", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-amd64-k8-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-amd64-k8-smp-2.6.12-10.30
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-amd64-xeon", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-amd64-xeon-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-amd64-xeon-2.6.12-10.30
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-iseries-smp", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-iseries-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-iseries-smp-2.6.12-10.30
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-k7", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-k7-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-k7-2.6.12-10.30
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-k7-smp", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-k7-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-k7-smp-2.6.12-10.30
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-powerpc", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-powerpc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-powerpc-2.6.12-10.30
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-powerpc-smp", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-powerpc-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-powerpc-smp-2.6.12-10.30
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-powerpc64-smp", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-powerpc64-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-powerpc64-smp-2.6.12-10.30
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-386", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-386-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-386-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-686", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-686-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-686-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-686-smp", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-686-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-686-smp-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-amd64-generic", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-amd64-generic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-amd64-generic-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-amd64-k8", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-amd64-k8-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-amd64-k8-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-amd64-k8-smp", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-amd64-k8-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-amd64-k8-smp-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-amd64-xeon", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-amd64-xeon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-amd64-xeon-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-k7", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-k7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-k7-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-k7-smp", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-k7-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-k7-smp-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-power3", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-power3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-power3-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-power3-smp", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-power3-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-power3-smp-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-power4", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-power4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-power4-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-power4-smp", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-power4-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-power4-smp-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-powerpc", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-powerpc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-powerpc-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-powerpc-smp", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-powerpc-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-powerpc-smp-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-386", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-386-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-386-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-686", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-686-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-686-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-686-smp", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-686-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-686-smp-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-amd64-generic", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-amd64-generic-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-amd64-generic-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-amd64-k8", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-amd64-k8-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-amd64-k8-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-amd64-k8-smp", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-amd64-k8-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-amd64-k8-smp-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-amd64-xeon", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-amd64-xeon-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-amd64-xeon-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-k7", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-k7-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-k7-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-k7-smp", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-k7-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-k7-smp-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-power3", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-power3-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-power3-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-power3-smp", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-power3-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-power3-smp-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-power4", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-power4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-power4-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-power4-smp", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-power4-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-power4-smp-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-powerpc", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-powerpc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-powerpc-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-powerpc-smp", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-powerpc-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-powerpc-smp-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-386", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-386-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-386-2.6.12-10.30
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-686", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-686-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-686-2.6.12-10.30
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-686-smp", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-686-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-686-smp-2.6.12-10.30
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-amd64-generic", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-amd64-generic-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-amd64-generic-2.6.12-10.30
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-amd64-k8", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-amd64-k8-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-amd64-k8-2.6.12-10.30
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-amd64-k8-smp", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-amd64-k8-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-amd64-k8-smp-2.6.12-10.30
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-amd64-xeon", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-amd64-xeon-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-amd64-xeon-2.6.12-10.30
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-iseries-smp", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-iseries-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-iseries-smp-2.6.12-10.30
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-k7", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-k7-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-k7-2.6.12-10.30
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-k7-smp", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-k7-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-k7-smp-2.6.12-10.30
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-powerpc", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-powerpc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-powerpc-2.6.12-10.30
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-powerpc-smp", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-powerpc-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-powerpc-smp-2.6.12-10.30
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-powerpc64-smp", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-powerpc64-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-powerpc64-smp-2.6.12-10.30
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-386", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-386-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-386-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-686", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-686-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-686-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-686-smp", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-686-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-686-smp-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-amd64-generic", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-amd64-generic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-amd64-generic-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-amd64-k8", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-amd64-k8-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-amd64-k8-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-amd64-k8-smp", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-amd64-k8-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-amd64-k8-smp-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-amd64-xeon", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-amd64-xeon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-amd64-xeon-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-k7", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-k7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-k7-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-k7-smp", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-k7-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-k7-smp-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-power3", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-power3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-power3-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-power3-smp", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-power3-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-power3-smp-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-power4", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-power4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-power4-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-power4-smp", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-power4-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-power4-smp-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-powerpc", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-powerpc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-powerpc-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-powerpc-smp", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-powerpc-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-powerpc-smp-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-patch-debian-2.6.8.1", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-patch-debian-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-patch-debian-2.6.8.1-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-patch-ubuntu-2.6.10", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-patch-ubuntu-2.6.10-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-patch-ubuntu-2.6.10-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-patch-ubuntu-2.6.12", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-patch-ubuntu-2.6.12-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-patch-ubuntu-2.6.12-2.6.12-10.30
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-source-2.6.10", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-source-2.6.10-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-source-2.6.10-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-source-2.6.12", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-source-2.6.12-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-source-2.6.12-2.6.12-10.30
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-source-2.6.8.1", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-source-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-source-2.6.8.1-2.6.8.1-16.28
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-tree-2.6.10", pkgver: "2.6.10-34.12");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-tree-2.6.10-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-tree-2.6.10-2.6.10-34.12
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-tree-2.6.12", pkgver: "2.6.12-10.30");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-tree-2.6.12-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-tree-2.6.12-2.6.12-10.30
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-tree-2.6.8.1", pkgver: "2.6.8.1-16.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-tree-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-tree-2.6.8.1-2.6.8.1-16.28
');
}

if (w) { security_hole(port: 0, data: desc); }
