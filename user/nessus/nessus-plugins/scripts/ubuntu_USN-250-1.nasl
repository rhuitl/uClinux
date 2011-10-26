# This script was automatically generated from the 250-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- linux-doc-2.6.12 
- linux-headers-2.6.12-10 
- linux-headers-2.6.12-10-386 
- linux-headers-2.6.12-10-686 
- linux-headers-2.6.12-10-686-smp 
- linux-headers-2.6.12-10-amd64-generic 
- linux-headers-2.6.12-10-amd64-k8 
- linux-headers-2.6.12-10-amd64-k8-smp 
- linux-headers-2.6.12-10-amd64-xeon 
- linux-headers-2.6.12-10-iseries-smp 
- linux-headers-2.6.12-10-k7 
- linux-headers-2.6.12-10-k7-smp 
- linux-headers-2.6.12-10-powerpc 
- linux-headers-2.6.1
[...]

Description :

Herbert Xu discovered a remote Denial of Service vulnerability in the
ICMP packet handler. In some situations a memory allocation was
released twice, which led to memory corruption. A remote attacker
could exploit this to crash the machine.

Solution :

Upgrade to : 
- linux-doc-2.6.12-2.6.12-10.28 (Ubuntu 5.10)
- linux-headers-2.6.12-10-2.6.12-10.28 (Ubuntu 5.10)
- linux-headers-2.6.12-10-386-2.6.12-10.28 (Ubuntu 5.10)
- linux-headers-2.6.12-10-686-2.6.12-10.28 (Ubuntu 5.10)
- linux-headers-2.6.12-10-686-smp-2.6.12-10.28 (Ubuntu 5.10)
- linux-headers-2.6.12-10-amd64-generic-2.6.12-10.28 (Ubuntu 5.10)
- linux-headers-2.6.12-10-amd64-k8-2.6.12-10.28 (Ubuntu 5.10)
- linux-headers-2.6.12-10-amd64-k8-smp-2.6.12-10.28 (Ubuntu 5.10)
- linux-headers-2.6.12-10-am
[...]


Risk factor : High
';

if (description) {
script_id(21059);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "250-1");
script_summary(english:"linux-source-2.6.12 vulnerability");
script_name(english:"USN250-1 : linux-source-2.6.12 vulnerability");
script_cve_id("CVE-2006-0454");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "linux-doc-2.6.12", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-doc-2.6.12-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-doc-2.6.12-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-386", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-386-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-386-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-686", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-686-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-686-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-686-smp", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-686-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-686-smp-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-amd64-generic", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-amd64-generic-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-amd64-generic-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-amd64-k8", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-amd64-k8-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-amd64-k8-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-amd64-k8-smp", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-amd64-k8-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-amd64-k8-smp-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-amd64-xeon", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-amd64-xeon-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-amd64-xeon-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-iseries-smp", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-iseries-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-iseries-smp-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-k7", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-k7-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-k7-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-k7-smp", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-k7-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-k7-smp-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-powerpc", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-powerpc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-powerpc-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-powerpc-smp", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-powerpc-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-powerpc-smp-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-powerpc64-smp", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-powerpc64-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-powerpc64-smp-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-386", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-386-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-386-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-686", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-686-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-686-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-686-smp", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-686-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-686-smp-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-amd64-generic", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-amd64-generic-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-amd64-generic-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-amd64-k8", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-amd64-k8-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-amd64-k8-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-amd64-k8-smp", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-amd64-k8-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-amd64-k8-smp-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-amd64-xeon", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-amd64-xeon-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-amd64-xeon-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-iseries-smp", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-iseries-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-iseries-smp-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-k7", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-k7-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-k7-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-k7-smp", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-k7-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-k7-smp-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-powerpc", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-powerpc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-powerpc-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-powerpc-smp", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-powerpc-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-powerpc-smp-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-powerpc64-smp", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-powerpc64-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-powerpc64-smp-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-patch-ubuntu-2.6.12", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-patch-ubuntu-2.6.12-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-patch-ubuntu-2.6.12-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-source-2.6.12", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-source-2.6.12-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-source-2.6.12-2.6.12-10.28
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-tree-2.6.12", pkgver: "2.6.12-10.28");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-tree-2.6.12-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-tree-2.6.12-2.6.12-10.28
');
}

if (w) { security_hole(port: 0, data: desc); }
