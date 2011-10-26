# This script was automatically generated from the 244-1 Ubuntu Security Notice
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

Doug Chapman discovered a flaw in the reference counting in the
sys_mq_open() function. By calling this function in a special way, a
local attacker could exploit this to cause a kernel crash.
(CVE-2005-3356)

Karl Janmar discovered that the /proc file system module used signed
data types in a wrong way. A local attacker could exploit this to read
random kernel memory, which could possibly contain sensitive data like
passwords or private keys. (CVE-2005-4605)

Yi Yang discovered an off-by-one buffer overflow in the sysctl()
system call. By calling sysctl with a specially crafted long string, a
local attacker could exploit this to crash the kernel or possibly even
execute arbitrary code with full kernel privileges. (CVE-2005-4618)

Perceval Anichini found a buffer overflow in the TwinHan DST
Frontend/Card DVB driver. A local user could exploit this to crash the
kernel or possibly execute arbitrary code with full kernel privileges.
This only affects Ubuntu 5.10. (CVE-2005-4639)

Stefan Rompf discovered that the
[...]

Solution :

Upgrade to : 
- linux-doc-2.6.10-2.6.10-34.11 (Ubuntu 5.04)
- linux-doc-2.6.12-2.6.12-10.26 (Ubuntu 5.10)
- linux-doc-2.6.8.1-2.6.8.1-16.27 (Ubuntu 4.10)
- linux-headers-2.6.10-6-2.6.10-34.11 (Ubuntu 5.04)
- linux-headers-2.6.10-6-386-2.6.10-34.11 (Ubuntu 5.04)
- linux-headers-2.6.10-6-686-2.6.10-34.11 (Ubuntu 5.04)
- linux-headers-2.6.10-6-686-smp-2.6.10-34.11 (Ubuntu 5.04)
- linux-headers-2.6.10-6-amd64-generic-2.6.10-34.11 (Ubuntu 5.04)
- linux-headers-2.6.10-6-amd64-k8-2.6.10-34.11 (Ubuntu 5.04)
- linu
[...]


Risk factor : High
';

if (description) {
script_id(20791);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "244-1");
script_summary(english:"linux-source-2.6.8.1/-2.6.10/-2.6.12 vulnerabilities");
script_name(english:"USN244-1 : linux-source-2.6.8.1/-2.6.10/-2.6.12 vulnerabilities");
script_cve_id("CVE-2005-3356","CVE-2005-4605","CVE-2005-4618","CVE-2005-4639","CVE-2006-0095","CVE-2006-0096");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "linux-doc-2.6.10", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-doc-2.6.10-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-doc-2.6.10-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-doc-2.6.12", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-doc-2.6.12-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-doc-2.6.12-2.6.12-10.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-doc-2.6.8.1", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-doc-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-doc-2.6.8.1-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-386", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-386-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-386-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-686", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-686-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-686-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-686-smp", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-686-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-686-smp-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-amd64-generic", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-amd64-generic-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-amd64-generic-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-amd64-k8", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-amd64-k8-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-amd64-k8-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-amd64-k8-smp", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-amd64-k8-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-amd64-k8-smp-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-amd64-xeon", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-amd64-xeon-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-amd64-xeon-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-k7", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-k7-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-k7-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-k7-smp", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-k7-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-k7-smp-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-power3", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-power3-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-power3-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-power3-smp", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-power3-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-power3-smp-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-power4", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-power4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-power4-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-power4-smp", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-power4-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-power4-smp-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-powerpc", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-powerpc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-powerpc-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-powerpc-smp", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-powerpc-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-powerpc-smp-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-2.6.12-10.26
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-386", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-386-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-386-2.6.12-10.26
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-686", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-686-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-686-2.6.12-10.26
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-686-smp", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-686-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-686-smp-2.6.12-10.26
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-amd64-generic", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-amd64-generic-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-amd64-generic-2.6.12-10.26
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-amd64-k8", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-amd64-k8-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-amd64-k8-2.6.12-10.26
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-amd64-k8-smp", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-amd64-k8-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-amd64-k8-smp-2.6.12-10.26
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-amd64-xeon", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-amd64-xeon-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-amd64-xeon-2.6.12-10.26
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-iseries-smp", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-iseries-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-iseries-smp-2.6.12-10.26
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-k7", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-k7-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-k7-2.6.12-10.26
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-k7-smp", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-k7-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-k7-smp-2.6.12-10.26
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-powerpc", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-powerpc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-powerpc-2.6.12-10.26
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-powerpc-smp", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-powerpc-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-powerpc-smp-2.6.12-10.26
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-powerpc64-smp", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-powerpc64-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-powerpc64-smp-2.6.12-10.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-386", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-386-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-386-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-686", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-686-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-686-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-686-smp", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-686-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-686-smp-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-amd64-generic", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-amd64-generic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-amd64-generic-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-amd64-k8", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-amd64-k8-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-amd64-k8-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-amd64-k8-smp", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-amd64-k8-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-amd64-k8-smp-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-amd64-xeon", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-amd64-xeon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-amd64-xeon-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-k7", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-k7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-k7-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-k7-smp", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-k7-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-k7-smp-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-power3", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-power3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-power3-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-power3-smp", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-power3-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-power3-smp-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-power4", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-power4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-power4-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-power4-smp", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-power4-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-power4-smp-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-powerpc", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-powerpc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-powerpc-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-powerpc-smp", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-powerpc-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-powerpc-smp-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-386", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-386-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-386-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-686", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-686-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-686-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-686-smp", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-686-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-686-smp-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-amd64-generic", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-amd64-generic-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-amd64-generic-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-amd64-k8", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-amd64-k8-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-amd64-k8-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-amd64-k8-smp", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-amd64-k8-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-amd64-k8-smp-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-amd64-xeon", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-amd64-xeon-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-amd64-xeon-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-k7", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-k7-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-k7-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-k7-smp", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-k7-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-k7-smp-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-power3", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-power3-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-power3-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-power3-smp", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-power3-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-power3-smp-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-power4", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-power4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-power4-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-power4-smp", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-power4-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-power4-smp-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-powerpc", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-powerpc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-powerpc-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-powerpc-smp", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-powerpc-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-powerpc-smp-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-386", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-386-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-386-2.6.12-10.26
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-686", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-686-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-686-2.6.12-10.26
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-686-smp", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-686-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-686-smp-2.6.12-10.26
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-amd64-generic", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-amd64-generic-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-amd64-generic-2.6.12-10.26
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-amd64-k8", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-amd64-k8-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-amd64-k8-2.6.12-10.26
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-amd64-k8-smp", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-amd64-k8-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-amd64-k8-smp-2.6.12-10.26
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-amd64-xeon", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-amd64-xeon-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-amd64-xeon-2.6.12-10.26
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-iseries-smp", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-iseries-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-iseries-smp-2.6.12-10.26
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-k7", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-k7-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-k7-2.6.12-10.26
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-k7-smp", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-k7-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-k7-smp-2.6.12-10.26
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-powerpc", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-powerpc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-powerpc-2.6.12-10.26
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-powerpc-smp", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-powerpc-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-powerpc-smp-2.6.12-10.26
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-powerpc64-smp", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-powerpc64-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-powerpc64-smp-2.6.12-10.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-386", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-386-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-386-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-686", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-686-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-686-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-686-smp", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-686-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-686-smp-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-amd64-generic", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-amd64-generic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-amd64-generic-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-amd64-k8", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-amd64-k8-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-amd64-k8-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-amd64-k8-smp", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-amd64-k8-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-amd64-k8-smp-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-amd64-xeon", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-amd64-xeon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-amd64-xeon-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-k7", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-k7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-k7-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-k7-smp", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-k7-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-k7-smp-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-power3", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-power3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-power3-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-power3-smp", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-power3-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-power3-smp-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-power4", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-power4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-power4-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-power4-smp", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-power4-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-power4-smp-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-powerpc", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-powerpc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-powerpc-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-powerpc-smp", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-powerpc-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-powerpc-smp-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-patch-debian-2.6.8.1", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-patch-debian-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-patch-debian-2.6.8.1-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-patch-ubuntu-2.6.10", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-patch-ubuntu-2.6.10-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-patch-ubuntu-2.6.10-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-patch-ubuntu-2.6.12", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-patch-ubuntu-2.6.12-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-patch-ubuntu-2.6.12-2.6.12-10.26
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-source-2.6.10", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-source-2.6.10-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-source-2.6.10-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-source-2.6.12", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-source-2.6.12-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-source-2.6.12-2.6.12-10.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-source-2.6.8.1", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-source-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-source-2.6.8.1-2.6.8.1-16.27
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-tree-2.6.10", pkgver: "2.6.10-34.11");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-tree-2.6.10-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-tree-2.6.10-2.6.10-34.11
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-tree-2.6.12", pkgver: "2.6.12-10.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-tree-2.6.12-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-tree-2.6.12-2.6.12-10.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-tree-2.6.8.1", pkgver: "2.6.8.1-16.27");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-tree-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-tree-2.6.8.1-2.6.8.1-16.27
');
}

if (w) { security_hole(port: 0, data: desc); }
