# This script was automatically generated from the 231-1 Ubuntu Security Notice
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

Rudolf Polzer reported an abuse of the \'loadkeys\' command. By
redefining one or more keys and tricking another user (like root) into
logging in on a text console and typing something that involves the
redefined keys, a local user could cause execution of arbitrary
commands with the privileges of the target user. The updated kernel
restricts the usage of \'loadkeys\' to root. (CVE-2005-3257)

The ptrace() system call did not correctly check whether a process
tried to attach to itself. A local attacker could exploit this to
cause a kernel crash. (CVE-2005-3783)

A Denial of Service vulnerability was found in the handler that
automatically cleans up and terminates child processes that are not
correctly handled by their parent process ("auto-reaper"). The check
did not correctly handle processes which were currently traced by
another process. A local attacker could exploit this to cause a kernel
crash. (CVE-2005-3784)

A locking problem was discovered in the POSIX timer cleanup handling
on process exit. A loca
[...]

Solution :

Upgrade to : 
- linux-doc-2.6.10-2.6.10-34.9 (Ubuntu 5.04)
- linux-doc-2.6.12-2.6.12-10.25 (Ubuntu 5.10)
- linux-doc-2.6.8.1-2.6.8.1-16.26 (Ubuntu 4.10)
- linux-headers-2.6.10-6-2.6.10-34.9 (Ubuntu 5.04)
- linux-headers-2.6.10-6-386-2.6.10-34.9 (Ubuntu 5.04)
- linux-headers-2.6.10-6-686-2.6.10-34.9 (Ubuntu 5.04)
- linux-headers-2.6.10-6-686-smp-2.6.10-34.9 (Ubuntu 5.04)
- linux-headers-2.6.10-6-amd64-generic-2.6.10-34.9 (Ubuntu 5.04)
- linux-headers-2.6.10-6-amd64-k8-2.6.10-34.9 (Ubuntu 5.04)
- linux-heade
[...]


Risk factor : High
';

if (description) {
script_id(20775);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "231-1");
script_summary(english:"linux-source-2.6.8.1/-2.6.10/-2.6.12 vulnerabilities");
script_name(english:"USN231-1 : linux-source-2.6.8.1/-2.6.10/-2.6.12 vulnerabilities");
script_cve_id("CVE-2005-3257","CVE-2005-3783","CVE-2005-3784","CVE-2005-3805","CVE-2005-3806","CVE-2005-3807","CVE-2005-3808","CVE-2005-3848","CVE-2005-3857","CVE-2005-3858");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "linux-doc-2.6.10", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-doc-2.6.10-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-doc-2.6.10-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-doc-2.6.12", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-doc-2.6.12-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-doc-2.6.12-2.6.12-10.25
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-doc-2.6.8.1", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-doc-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-doc-2.6.8.1-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-386", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-386-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-386-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-686", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-686-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-686-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-686-smp", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-686-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-686-smp-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-amd64-generic", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-amd64-generic-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-amd64-generic-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-amd64-k8", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-amd64-k8-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-amd64-k8-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-amd64-k8-smp", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-amd64-k8-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-amd64-k8-smp-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-amd64-xeon", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-amd64-xeon-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-amd64-xeon-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-k7", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-k7-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-k7-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-k7-smp", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-k7-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-k7-smp-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-power3", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-power3-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-power3-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-power3-smp", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-power3-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-power3-smp-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-power4", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-power4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-power4-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-power4-smp", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-power4-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-power4-smp-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-powerpc", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-powerpc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-powerpc-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-powerpc-smp", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.10-6-powerpc-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-powerpc-smp-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-2.6.12-10.25
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-386", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-386-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-386-2.6.12-10.25
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-686", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-686-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-686-2.6.12-10.25
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-686-smp", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-686-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-686-smp-2.6.12-10.25
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-amd64-generic", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-amd64-generic-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-amd64-generic-2.6.12-10.25
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-amd64-k8", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-amd64-k8-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-amd64-k8-2.6.12-10.25
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-amd64-k8-smp", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-amd64-k8-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-amd64-k8-smp-2.6.12-10.25
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-amd64-xeon", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-amd64-xeon-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-amd64-xeon-2.6.12-10.25
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-iseries-smp", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-iseries-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-iseries-smp-2.6.12-10.25
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-k7", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-k7-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-k7-2.6.12-10.25
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-k7-smp", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-k7-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-k7-smp-2.6.12-10.25
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-powerpc", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-powerpc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-powerpc-2.6.12-10.25
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-powerpc-smp", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-powerpc-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-powerpc-smp-2.6.12-10.25
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-powerpc64-smp", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.12-10-powerpc64-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-powerpc64-smp-2.6.12-10.25
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-386", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-386-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-386-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-686", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-686-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-686-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-686-smp", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-686-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-686-smp-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-amd64-generic", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-amd64-generic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-amd64-generic-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-amd64-k8", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-amd64-k8-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-amd64-k8-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-amd64-k8-smp", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-amd64-k8-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-amd64-k8-smp-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-amd64-xeon", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-amd64-xeon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-amd64-xeon-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-k7", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-k7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-k7-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-k7-smp", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-k7-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-k7-smp-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-power3", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-power3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-power3-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-power3-smp", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-power3-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-power3-smp-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-power4", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-power4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-power4-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-power4-smp", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-power4-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-power4-smp-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-powerpc", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-powerpc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-powerpc-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-6-powerpc-smp", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-6-powerpc-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-6-powerpc-smp-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-386", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-386-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-386-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-686", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-686-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-686-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-686-smp", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-686-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-686-smp-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-amd64-generic", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-amd64-generic-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-amd64-generic-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-amd64-k8", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-amd64-k8-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-amd64-k8-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-amd64-k8-smp", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-amd64-k8-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-amd64-k8-smp-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-amd64-xeon", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-amd64-xeon-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-amd64-xeon-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-k7", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-k7-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-k7-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-k7-smp", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-k7-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-k7-smp-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-power3", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-power3-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-power3-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-power3-smp", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-power3-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-power3-smp-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-power4", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-power4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-power4-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-power4-smp", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-power4-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-power4-smp-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-powerpc", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-powerpc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-powerpc-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-powerpc-smp", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.10-6-powerpc-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-powerpc-smp-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-386", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-386-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-386-2.6.12-10.25
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-686", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-686-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-686-2.6.12-10.25
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-686-smp", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-686-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-686-smp-2.6.12-10.25
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-amd64-generic", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-amd64-generic-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-amd64-generic-2.6.12-10.25
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-amd64-k8", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-amd64-k8-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-amd64-k8-2.6.12-10.25
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-amd64-k8-smp", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-amd64-k8-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-amd64-k8-smp-2.6.12-10.25
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-amd64-xeon", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-amd64-xeon-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-amd64-xeon-2.6.12-10.25
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-iseries-smp", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-iseries-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-iseries-smp-2.6.12-10.25
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-k7", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-k7-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-k7-2.6.12-10.25
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-k7-smp", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-k7-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-k7-smp-2.6.12-10.25
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-powerpc", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-powerpc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-powerpc-2.6.12-10.25
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-powerpc-smp", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-powerpc-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-powerpc-smp-2.6.12-10.25
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-powerpc64-smp", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.12-10-powerpc64-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-powerpc64-smp-2.6.12-10.25
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-386", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-386-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-386-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-686", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-686-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-686-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-686-smp", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-686-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-686-smp-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-amd64-generic", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-amd64-generic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-amd64-generic-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-amd64-k8", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-amd64-k8-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-amd64-k8-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-amd64-k8-smp", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-amd64-k8-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-amd64-k8-smp-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-amd64-xeon", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-amd64-xeon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-amd64-xeon-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-k7", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-k7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-k7-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-k7-smp", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-k7-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-k7-smp-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-power3", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-power3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-power3-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-power3-smp", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-power3-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-power3-smp-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-power4", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-power4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-power4-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-power4-smp", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-power4-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-power4-smp-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-powerpc", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-powerpc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-powerpc-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-6-powerpc-smp", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-6-powerpc-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-6-powerpc-smp-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-patch-debian-2.6.8.1", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-patch-debian-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-patch-debian-2.6.8.1-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-patch-ubuntu-2.6.10", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-patch-ubuntu-2.6.10-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-patch-ubuntu-2.6.10-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-patch-ubuntu-2.6.12", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-patch-ubuntu-2.6.12-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-patch-ubuntu-2.6.12-2.6.12-10.25
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-source-2.6.10", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-source-2.6.10-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-source-2.6.10-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-source-2.6.12", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-source-2.6.12-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-source-2.6.12-2.6.12-10.25
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-source-2.6.8.1", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-source-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-source-2.6.8.1-2.6.8.1-16.26
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-tree-2.6.10", pkgver: "2.6.10-34.9");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-tree-2.6.10-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-tree-2.6.10-2.6.10-34.9
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-tree-2.6.12", pkgver: "2.6.12-10.25");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-tree-2.6.12-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-tree-2.6.12-2.6.12-10.25
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-tree-2.6.8.1", pkgver: "2.6.8.1-16.26");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-tree-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-tree-2.6.8.1-2.6.8.1-16.26
');
}

if (w) { security_hole(port: 0, data: desc); }
