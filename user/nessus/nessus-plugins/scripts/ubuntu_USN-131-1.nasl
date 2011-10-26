# This script was automatically generated from the 131-1 Ubuntu Security Notice
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
- linux-doc-2.6.8.1 
- linux-headers-2.6.10-5 
- linux-headers-2.6.10-5-386 
- linux-headers-2.6.10-5-686 
- linux-headers-2.6.10-5-686-smp 
- linux-headers-2.6.10-5-amd64-generic 
- linux-headers-2.6.10-5-amd64-k8 
- linux-headers-2.6.10-5-amd64-k8-smp 
- linux-headers-2.6.10-5-amd64-xeon 
- linux-headers-2.6.10-5-k7 
- linux-headers-2.6.10-5-k7-smp 
- linux-headers-2.6.10-5-power3 
- linux-headers-2.6.10-5-power3-smp 
- linux-header
[...]

Description :

Colin Percival discovered an information disclosure in the "Hyper
Threading Technology" architecture in processors which are capable of
simultaneous multithreading (in particular Intel Pentium 4, Intel
Mobile Pentium 4, and Intel Xeon processors). This allows a malicious
thread to monitor the execution of another thread on the same CPU.
This could be exploited to steal cryptographic keys, passwords, or
other arbitrary data from unrelated processes. Since it is not
possible to provide a safe patch in a short time, HyperThreading has
been disabled in the updated kernel packages for now. You can manually
enable HyperThreading again by passing the kernel parameter "ht=on" at
boot. (CVE-2005-0109)

A Denial of Service vulnerability was discovered in the
fib_seq_start() function(). This allowed a local user to crash the
system by reading /proc/net/route in a certain way. (CVE-2005-1041)

Paul Starzetz found an integer overflow in the ELF binary format
loader\'s core dump function. By creating and executing a speci
[...]

Solution :

Upgrade to : 
- linux-doc-2.6.10-2.6.10-34.1 (Ubuntu 5.04)
- linux-doc-2.6.8.1-2.6.8.1-16.18 (Ubuntu 4.10)
- linux-headers-2.6.10-5-2.6.10-34.1 (Ubuntu 5.04)
- linux-headers-2.6.10-5-386-2.6.10-34.1 (Ubuntu 5.04)
- linux-headers-2.6.10-5-686-2.6.10-34.1 (Ubuntu 5.04)
- linux-headers-2.6.10-5-686-smp-2.6.10-34.1 (Ubuntu 5.04)
- linux-headers-2.6.10-5-amd64-generic-2.6.10-34.1 (Ubuntu 5.04)
- linux-headers-2.6.10-5-amd64-k8-2.6.10-34.1 (Ubuntu 5.04)
- linux-headers-2.6.10-5-amd64-k8-smp-2.6.10-34.1 (Ubuntu 5
[...]


Risk factor : High
';

if (description) {
script_id(20522);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "131-1");
script_summary(english:"linux-source-2.6.8.1, linux-source-2.6.10 vulnerabilities");
script_name(english:"USN131-1 : linux-source-2.6.8.1, linux-source-2.6.10 vulnerabilities");
script_cve_id("CVE-2005-0109","CVE-2005-1041","CVE-2005-1263","CVE-2005-1264","CVE-2005-1368","CVE-2005-1369","CVE-2005-1589");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "linux-doc-2.6.10", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-doc-2.6.10-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-doc-2.6.10-2.6.10-34.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-doc-2.6.8.1", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-doc-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-doc-2.6.8.1-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-5", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-5-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-5-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-5-386", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-5-386-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-5-386-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-5-686", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-5-686-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-5-686-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-5-686-smp", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-5-686-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-5-686-smp-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-5-amd64-generic", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-5-amd64-generic-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-5-amd64-generic-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-5-amd64-k8", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-5-amd64-k8-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-5-amd64-k8-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-5-amd64-k8-smp", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-5-amd64-k8-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-5-amd64-k8-smp-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-5-amd64-xeon", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-5-amd64-xeon-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-5-amd64-xeon-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-5-k7", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-5-k7-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-5-k7-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-5-k7-smp", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-5-k7-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-5-k7-smp-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-5-power3", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-5-power3-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-5-power3-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-5-power3-smp", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-5-power3-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-5-power3-smp-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-5-power4", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-5-power4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-5-power4-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-5-power4-smp", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-5-power4-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-5-power4-smp-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-5-powerpc", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-5-powerpc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-5-powerpc-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-5-powerpc-smp", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-5-powerpc-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-5-powerpc-smp-2.6.10-34.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-386", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-386-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-386-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-686", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-686-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-686-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-686-smp", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-686-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-686-smp-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-amd64-generic", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-amd64-generic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-amd64-generic-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-amd64-k8", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-amd64-k8-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-amd64-k8-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-amd64-k8-smp", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-amd64-k8-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-amd64-k8-smp-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-amd64-xeon", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-amd64-xeon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-amd64-xeon-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-k7", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-k7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-k7-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-k7-smp", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-k7-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-k7-smp-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-power3", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-power3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-power3-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-power3-smp", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-power3-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-power3-smp-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-power4", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-power4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-power4-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-power4-smp", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-power4-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-power4-smp-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-powerpc", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-powerpc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-powerpc-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-5-powerpc-smp", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-5-powerpc-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-5-powerpc-smp-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-5-386", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-5-386-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-5-386-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-5-686", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-5-686-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-5-686-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-5-686-smp", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-5-686-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-5-686-smp-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-5-amd64-generic", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-5-amd64-generic-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-5-amd64-generic-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-5-amd64-k8", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-5-amd64-k8-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-5-amd64-k8-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-5-amd64-k8-smp", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-5-amd64-k8-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-5-amd64-k8-smp-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-5-amd64-xeon", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-5-amd64-xeon-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-5-amd64-xeon-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-5-k7", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-5-k7-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-5-k7-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-5-k7-smp", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-5-k7-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-5-k7-smp-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-5-power3", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-5-power3-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-5-power3-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-5-power3-smp", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-5-power3-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-5-power3-smp-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-5-power4", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-5-power4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-5-power4-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-5-power4-smp", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-5-power4-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-5-power4-smp-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-5-powerpc", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-5-powerpc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-5-powerpc-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-5-powerpc-smp", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-5-powerpc-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-5-powerpc-smp-2.6.10-34.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-386", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-386-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-386-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-686", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-686-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-686-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-686-smp", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-686-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-686-smp-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-amd64-generic", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-amd64-generic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-amd64-generic-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-amd64-k8", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-amd64-k8-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-amd64-k8-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-amd64-k8-smp", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-amd64-k8-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-amd64-k8-smp-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-amd64-xeon", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-amd64-xeon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-amd64-xeon-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-k7", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-k7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-k7-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-k7-smp", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-k7-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-k7-smp-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-power3", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-power3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-power3-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-power3-smp", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-power3-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-power3-smp-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-power4", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-power4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-power4-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-power4-smp", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-power4-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-power4-smp-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-powerpc", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-powerpc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-powerpc-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-5-powerpc-smp", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-5-powerpc-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-5-powerpc-smp-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-patch-debian-2.6.8.1", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-patch-debian-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-patch-debian-2.6.8.1-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-patch-ubuntu-2.6.10", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-patch-ubuntu-2.6.10-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-patch-ubuntu-2.6.10-2.6.10-34.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-source-2.6.10", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-source-2.6.10-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-source-2.6.10-2.6.10-34.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-source-2.6.8.1", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-source-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-source-2.6.8.1-2.6.8.1-16.18
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-tree-2.6.10", pkgver: "2.6.10-34.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-tree-2.6.10-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-tree-2.6.10-2.6.10-34.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-tree-2.6.8.1", pkgver: "2.6.8.1-16.18");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-tree-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-tree-2.6.8.1-2.6.8.1-16.18
');
}

if (w) { security_hole(port: 0, data: desc); }
