# This script was automatically generated from the 57-1 Ubuntu Security Notice
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
- linux-headers-2.6.8.1-4 
- linux-headers-2.6.8.1-4-386 
- linux-headers-2.6.8.1-4-686 
- linux-headers-2.6.8.1-4-686-smp 
- linux-headers-2.6.8.1-4-amd64-generic 
- linux-headers-2.6.8.1-4-amd64-k8 
- linux-headers-2.6.8.1-4-amd64-k8-smp 
- linux-headers-2.6.8.1-4-amd64-xeon 
- linux-headers-2.6.8.1-4-k7 
- linux-headers-2.6.8.1-4-k7-smp 
- linux-headers-2.6.8.1-4-power3 
- linux-headers-2.6.8.1-4-power3-smp 
- linux-headers-2.6.8.
[...]

Description :

Paul Starzetz discovered a race condition in the ELF library and a.out
binary format loaders, which can be locally exploited in several
different ways to gain root privileges. (CVE-2004-1235)

Liang Bin found a design flaw in the capability module. After this
module was loaded on demand in a running system, all unprivileged user
space processes got all kernel capabilities (thus essentially root
privileges). This is mitigated by the fact that the capability module
is loaded very early in the boot process of a standard Ubuntu system,
when no unprivileged user processes are yet running. (CVE-2004-1337)

Finally, this update fixes a memory leak in the ip_conntrack_ftp
iptables module. However, it is believed that this is not exploitable.

Solution :

Upgrade to : 
- linux-doc-2.6.8.1-2.6.8.1-16.8 (Ubuntu 4.10)
- linux-headers-2.6.8.1-4-2.6.8.1-16.8 (Ubuntu 4.10)
- linux-headers-2.6.8.1-4-386-2.6.8.1-16.8 (Ubuntu 4.10)
- linux-headers-2.6.8.1-4-686-2.6.8.1-16.8 (Ubuntu 4.10)
- linux-headers-2.6.8.1-4-686-smp-2.6.8.1-16.8 (Ubuntu 4.10)
- linux-headers-2.6.8.1-4-amd64-generic-2.6.8.1-16.8 (Ubuntu 4.10)
- linux-headers-2.6.8.1-4-amd64-k8-2.6.8.1-16.8 (Ubuntu 4.10)
- linux-headers-2.6.8.1-4-amd64-k8-smp-2.6.8.1-16.8 (Ubuntu 4.10)
- linux-headers-2.6.8.1-4-a
[...]


Risk factor : High
';

if (description) {
script_id(20675);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "57-1");
script_summary(english:"linux-source-2.6.8.1 vulnerabilities");
script_name(english:"USN57-1 : linux-source-2.6.8.1 vulnerabilities");
script_cve_id("CVE-2004-1235","CVE-2004-1337");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "linux-doc-2.6.8.1", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-doc-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-doc-2.6.8.1-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-386", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-386-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-386-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-686", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-686-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-686-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-686-smp", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-686-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-686-smp-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-amd64-generic", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-amd64-generic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-amd64-generic-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-amd64-k8", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-amd64-k8-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-amd64-k8-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-amd64-k8-smp", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-amd64-k8-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-amd64-k8-smp-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-amd64-xeon", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-amd64-xeon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-amd64-xeon-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-k7", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-k7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-k7-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-k7-smp", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-k7-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-k7-smp-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-power3", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-power3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-power3-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-power3-smp", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-power3-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-power3-smp-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-power4", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-power4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-power4-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-power4-smp", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-power4-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-power4-smp-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-powerpc", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-powerpc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-powerpc-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-powerpc-smp", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-powerpc-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-powerpc-smp-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-386", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-386-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-386-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-686", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-686-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-686-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-686-smp", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-686-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-686-smp-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-amd64-generic", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-amd64-generic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-amd64-generic-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-amd64-k8", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-amd64-k8-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-amd64-k8-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-amd64-k8-smp", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-amd64-k8-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-amd64-k8-smp-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-amd64-xeon", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-amd64-xeon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-amd64-xeon-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-k7", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-k7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-k7-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-k7-smp", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-k7-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-k7-smp-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-power3", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-power3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-power3-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-power3-smp", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-power3-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-power3-smp-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-power4", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-power4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-power4-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-power4-smp", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-power4-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-power4-smp-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-powerpc", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-powerpc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-powerpc-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-powerpc-smp", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-powerpc-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-powerpc-smp-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-patch-debian-2.6.8.1", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-patch-debian-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-patch-debian-2.6.8.1-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-source-2.6.8.1", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-source-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-source-2.6.8.1-2.6.8.1-16.8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-tree-2.6.8.1", pkgver: "2.6.8.1-16.8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-tree-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-tree-2.6.8.1-2.6.8.1-16.8
');
}

if (w) { security_hole(port: 0, data: desc); }
