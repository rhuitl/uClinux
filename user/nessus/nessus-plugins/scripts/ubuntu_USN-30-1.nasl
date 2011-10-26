# This script was automatically generated from the 30-1 Ubuntu Security Notice
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
- linux-headers-2.6.8.1-3 
- linux-headers-2.6.8.1-3-386 
- linux-headers-2.6.8.1-3-686 
- linux-headers-2.6.8.1-3-686-smp 
- linux-headers-2.6.8.1-3-amd64-generic 
- linux-headers-2.6.8.1-3-amd64-k8 
- linux-headers-2.6.8.1-3-amd64-k8-smp 
- linux-headers-2.6.8.1-3-amd64-xeon 
- linux-headers-2.6.8.1-3-k7 
- linux-headers-2.6.8.1-3-k7-smp 
- linux-headers-2.6.8.1-3-power3 
- linux-headers-2.6.8.1-3-power3-smp 
- linux-headers-2.6.8.
[...]

Description :

CVE-2004-0883, CVE-2004-0949:

  During an audit of the smb file system implementation within Linux,
  several vulnerabilities were discovered ranging from out of bounds
  read accesses to kernel level buffer overflows.
  
  To exploit any of these vulnerabilities, an attacker needs control
  over the answers of the connected Samba server. This could be
  achieved by man-in-the-middle attacks or by taking over the Samba
  server with e. g. the recently disclosed vulnerability in Samba 3.x
  (see CVE-2004-0882).
  
  While any of these vulnerabilities can be easily used as remote denial
  of service exploits against Linux systems, it is unclear if it is
  possible for a skilled local or remote attacker to use any of the
  possible buffer overflows for arbitrary code execution in kernel
  space. So these bugs may theoretically lead to privilege escalation
  and total compromise of the whole system.

http://isec.pl/vulnerabilities/isec-0017-binfmt_elf.txt:

  Several flaws have been found in the Linux ELF binar
[...]

Solution :

Upgrade to : 
- linux-doc-2.6.8.1-2.6.8.1-16.1 (Ubuntu 4.10)
- linux-headers-2.6.8.1-3-2.6.8.1-16.1 (Ubuntu 4.10)
- linux-headers-2.6.8.1-3-386-2.6.8.1-16.1 (Ubuntu 4.10)
- linux-headers-2.6.8.1-3-686-2.6.8.1-16.1 (Ubuntu 4.10)
- linux-headers-2.6.8.1-3-686-smp-2.6.8.1-16.1 (Ubuntu 4.10)
- linux-headers-2.6.8.1-3-amd64-generic-2.6.8.1-16.1 (Ubuntu 4.10)
- linux-headers-2.6.8.1-3-amd64-k8-2.6.8.1-16.1 (Ubuntu 4.10)
- linux-headers-2.6.8.1-3-amd64-k8-smp-2.6.8.1-16.1 (Ubuntu 4.10)
- linux-headers-2.6.8.1-3-a
[...]


Risk factor : High
';

if (description) {
script_id(20646);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "30-1");
script_summary(english:"linux-source-2.6.8.1 vulnerabilities");
script_name(english:"USN30-1 : linux-source-2.6.8.1 vulnerabilities");
script_cve_id("CVE-2004-0882","CVE-2004-0883","CVE-2004-0949");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "linux-doc-2.6.8.1", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-doc-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-doc-2.6.8.1-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-3", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-3-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-3-386", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-3-386-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-3-386-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-3-686", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-3-686-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-3-686-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-3-686-smp", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-3-686-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-3-686-smp-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-3-amd64-generic", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-3-amd64-generic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-3-amd64-generic-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-3-amd64-k8", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-3-amd64-k8-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-3-amd64-k8-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-3-amd64-k8-smp", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-3-amd64-k8-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-3-amd64-k8-smp-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-3-amd64-xeon", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-3-amd64-xeon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-3-amd64-xeon-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-3-k7", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-3-k7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-3-k7-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-3-k7-smp", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-3-k7-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-3-k7-smp-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-3-power3", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-3-power3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-3-power3-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-3-power3-smp", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-3-power3-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-3-power3-smp-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-3-power4", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-3-power4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-3-power4-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-3-power4-smp", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-3-power4-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-3-power4-smp-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-3-powerpc", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-3-powerpc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-3-powerpc-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-3-powerpc-smp", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-3-powerpc-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-3-powerpc-smp-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-3-386", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-3-386-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-3-386-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-3-686", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-3-686-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-3-686-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-3-686-smp", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-3-686-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-3-686-smp-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-3-amd64-generic", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-3-amd64-generic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-3-amd64-generic-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-3-amd64-k8", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-3-amd64-k8-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-3-amd64-k8-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-3-amd64-k8-smp", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-3-amd64-k8-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-3-amd64-k8-smp-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-3-amd64-xeon", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-3-amd64-xeon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-3-amd64-xeon-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-3-k7", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-3-k7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-3-k7-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-3-k7-smp", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-3-k7-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-3-k7-smp-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-3-power3", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-3-power3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-3-power3-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-3-power3-smp", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-3-power3-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-3-power3-smp-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-3-power4", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-3-power4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-3-power4-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-3-power4-smp", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-3-power4-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-3-power4-smp-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-3-powerpc", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-3-powerpc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-3-powerpc-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-3-powerpc-smp", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-3-powerpc-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-3-powerpc-smp-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-patch-debian-2.6.8.1", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-patch-debian-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-patch-debian-2.6.8.1-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-source-2.6.8.1", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-source-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-source-2.6.8.1-2.6.8.1-16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-tree-2.6.8.1", pkgver: "2.6.8.1-16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-tree-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-tree-2.6.8.1-2.6.8.1-16.1
');
}

if (w) { security_hole(port: 0, data: desc); }
