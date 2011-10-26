# This script was automatically generated from the 110-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- linux-doc-2.6.8.1 
- linux-headers-2.6.8.1-5 
- linux-headers-2.6.8.1-5-386 
- linux-headers-2.6.8.1-5-686 
- linux-headers-2.6.8.1-5-686-smp 
- linux-headers-2.6.8.1-5-amd64-generic 
- linux-headers-2.6.8.1-5-amd64-k8 
- linux-headers-2.6.8.1-5-amd64-k8-smp 
- linux-headers-2.6.8.1-5-amd64-xeon 
- linux-headers-2.6.8.1-5-k7 
- linux-headers-2.6.8.1-5-k7-smp 
- linux-headers-2.6.8.1-5-power3 
- linux-headers-2.6.8.1-5-power3-smp 
- linux-headers-2.6.8.
[...]

Description :

Alexander Nyberg discovered an integer overflow in the
sysfs_write_file() function. A local attacker could exploit this to
crash the kernel or possibly even execute arbitrary code with root
privileges by writing to an user-writable file in /sys under certain
low-memory conditions. However, there are very few cases where a
user-writeable sysfs file actually exists. (CVE-2005-0867)

Olof Johansson discovered a Denial of Service vulnerability in the
futex functions, which provide semaphores for exclusive locking of
resources. A local attacker could possibly exploit this to cause a
kernel deadlock. (CVE-2005-0937)

In addition this update fixes two race conditions in the ext3 and jfs
file system drivers, which could lead to a kernel crash under certain
(unusual) conditions. However, these cannot easily be triggered by
users, thus they are not security sensitive.
(http://linux.bkbits.net:8080/linux-2.5/gnupatch@4248d87aETPJX79hVXl4owAUwu2SmQ,
http://linux.bkbits.net:8080/linux-2.6/cset@1.2181.46.242)

Solution :

Upgrade to : 
- linux-doc-2.6.8.1-2.6.8.1-16.14 (Ubuntu 4.10)
- linux-headers-2.6.8.1-5-2.6.8.1-16.14 (Ubuntu 4.10)
- linux-headers-2.6.8.1-5-386-2.6.8.1-16.14 (Ubuntu 4.10)
- linux-headers-2.6.8.1-5-686-2.6.8.1-16.14 (Ubuntu 4.10)
- linux-headers-2.6.8.1-5-686-smp-2.6.8.1-16.14 (Ubuntu 4.10)
- linux-headers-2.6.8.1-5-amd64-generic-2.6.8.1-16.14 (Ubuntu 4.10)
- linux-headers-2.6.8.1-5-amd64-k8-2.6.8.1-16.14 (Ubuntu 4.10)
- linux-headers-2.6.8.1-5-amd64-k8-smp-2.6.8.1-16.14 (Ubuntu 4.10)
- linux-headers-2.6
[...]


Risk factor : High
';

if (description) {
script_id(20497);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "110-1");
script_summary(english:"linux-source-2.6.8.1 vulnerabilities");
script_name(english:"USN110-1 : linux-source-2.6.8.1 vulnerabilities");
script_cve_id("CVE-2005-0867","CVE-2005-0937");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "linux-doc-2.6.8.1", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-doc-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-doc-2.6.8.1-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-386", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-386-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-386-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-686", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-686-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-686-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-686-smp", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-686-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-686-smp-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-amd64-generic", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-amd64-generic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-amd64-generic-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-amd64-k8", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-amd64-k8-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-amd64-k8-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-amd64-k8-smp", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-amd64-k8-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-amd64-k8-smp-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-amd64-xeon", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-amd64-xeon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-amd64-xeon-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-k7", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-k7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-k7-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-k7-smp", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-k7-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-k7-smp-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-power3", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-power3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-power3-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-power3-smp", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-power3-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-power3-smp-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-power4", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-power4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-power4-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-power4-smp", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-power4-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-power4-smp-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-powerpc", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-powerpc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-powerpc-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-powerpc-smp", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-powerpc-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-powerpc-smp-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-386", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-386-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-386-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-686", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-686-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-686-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-686-smp", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-686-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-686-smp-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-amd64-generic", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-amd64-generic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-amd64-generic-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-amd64-k8", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-amd64-k8-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-amd64-k8-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-amd64-k8-smp", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-amd64-k8-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-amd64-k8-smp-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-amd64-xeon", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-amd64-xeon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-amd64-xeon-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-k7", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-k7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-k7-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-k7-smp", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-k7-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-k7-smp-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-power3", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-power3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-power3-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-power3-smp", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-power3-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-power3-smp-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-power4", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-power4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-power4-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-power4-smp", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-power4-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-power4-smp-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-powerpc", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-powerpc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-powerpc-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-powerpc-smp", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-powerpc-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-powerpc-smp-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-patch-debian-2.6.8.1", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-patch-debian-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-patch-debian-2.6.8.1-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-source-2.6.8.1", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-source-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-source-2.6.8.1-2.6.8.1-16.14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-tree-2.6.8.1", pkgver: "2.6.8.1-16.14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-tree-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-tree-2.6.8.1-2.6.8.1-16.14
');
}

if (w) { security_hole(port: 0, data: desc); }
