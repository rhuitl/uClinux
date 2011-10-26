# This script was automatically generated from the 38-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- fglrx-control 
- fglrx-driver 
- fglrx-driver-dev 
- linux-386 
- linux-686 
- linux-686-smp 
- linux-amd64-generic 
- linux-amd64-k8 
- linux-amd64-k8-smp 
- linux-amd64-xeon 
- linux-doc 
- linux-doc-2.6.8.1 
- linux-headers-2.6-386 
- linux-headers-2.6-686 
- linux-headers-2.6-686-smp 
- linux-headers-2.6-amd64-generic 
- linux-headers-2.6-amd64-k8 
- linux-headers-2.6-amd64-k8-smp 
- linux-headers-2.6-amd64-xeon 
- linux-headers-2.6-k7 
- linux-hea
[...]

Description :

CVE-2004-0814:

  Vitaly V. Bursov discovered a Denial of Service vulnerability in the "serio"
  code; opening the same tty device twice and doing some particular operations on
  it caused a kernel panic and/or a system lockup.  

  Fixing this vulnerability required a change in the Application Binary
  Interface (ABI) of the kernel. This means that third party user installed
  modules might not work any more with the new kernel, so this fixed kernel got
  a new ABI version number. You have to recompile and reinstall all third party
  modules.

CVE-2004-1016:

  Paul Starzetz discovered a buffer overflow vulnerability in the "__scm_send"
  function which handles the sending of UDP network packets. A wrong validity
  check of the cmsghdr structure allowed a local attacker to modify kernel
  memory, thus causing an endless loop (Denial of Service) or possibly even
  root privilege escalation.

CVE-2004-1056:

  Thomas Hellström discovered a Denial of Service vulnerability in the Direct
  Rendering Manager (DRM
[...]

Solution :

Upgrade to : 
- fglrx-control-2.6.8.1.3-5 (Ubuntu 4.10)
- fglrx-driver-2.6.8.1.3-5 (Ubuntu 4.10)
- fglrx-driver-dev-2.6.8.1.3-5 (Ubuntu 4.10)
- linux-386-2.6.8.1-14 (Ubuntu 4.10)
- linux-686-2.6.8.1-14 (Ubuntu 4.10)
- linux-686-smp-2.6.8.1-14 (Ubuntu 4.10)
- linux-amd64-generic-2.6.8.1-14 (Ubuntu 4.10)
- linux-amd64-k8-2.6.8.1-14 (Ubuntu 4.10)
- linux-amd64-k8-smp-2.6.8.1-14 (Ubuntu 4.10)
- linux-amd64-xeon-2.6.8.1-14 (Ubuntu 4.10)
- linux-doc-2.6.8.1-14 (Ubuntu 4.10)
- linux-doc-2.6.8.1-2.6.8.1-16.3 (Ubun
[...]


Risk factor : High
';

if (description) {
script_id(20654);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "38-1");
script_summary(english:"linux-source-2.6.8.1 vulnerabilities");
script_name(english:"USN38-1 : linux-source-2.6.8.1 vulnerabilities");
script_cve_id("CVE-2004-0814","CVE-2004-1016","CVE-2004-1056","CVE-2004-1058","CVE-2004-1068","CVE-2004-1069","CVE-2004-1137","CVE-2004-1151");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "fglrx-control", pkgver: "2.6.8.1.3-5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package fglrx-control-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to fglrx-control-2.6.8.1.3-5
');
}
found = ubuntu_check(osver: "4.10", pkgname: "fglrx-driver", pkgver: "2.6.8.1.3-5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package fglrx-driver-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to fglrx-driver-2.6.8.1.3-5
');
}
found = ubuntu_check(osver: "4.10", pkgname: "fglrx-driver-dev", pkgver: "2.6.8.1.3-5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package fglrx-driver-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to fglrx-driver-dev-2.6.8.1.3-5
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-386", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-386-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-386-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-686", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-686-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-686-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-686-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-686-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-686-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-amd64-generic", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-amd64-generic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-amd64-generic-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-amd64-k8", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-amd64-k8-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-amd64-k8-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-amd64-k8-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-amd64-k8-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-amd64-k8-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-amd64-xeon", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-amd64-xeon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-amd64-xeon-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-doc", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-doc-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-doc-2.6.8.1", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-doc-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-doc-2.6.8.1-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6-386", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6-386-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6-386-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6-686", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6-686-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6-686-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6-686-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6-686-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6-686-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6-amd64-generic", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6-amd64-generic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6-amd64-generic-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6-amd64-k8", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6-amd64-k8-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6-amd64-k8-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6-amd64-k8-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6-amd64-k8-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6-amd64-k8-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6-amd64-xeon", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6-amd64-xeon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6-amd64-xeon-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6-k7", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6-k7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6-k7-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6-k7-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6-k7-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6-k7-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6-power3", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6-power3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6-power3-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6-power3-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6-power3-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6-power3-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6-power4", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6-power4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6-power4-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6-power4-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6-power4-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6-power4-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6-powerpc", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6-powerpc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6-powerpc-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6-powerpc-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6-powerpc-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6-powerpc-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-386", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-386-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-386-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-686", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-686-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-686-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-686-smp", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-686-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-686-smp-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-amd64-generic", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-amd64-generic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-amd64-generic-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-amd64-k8", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-amd64-k8-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-amd64-k8-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-amd64-k8-smp", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-amd64-k8-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-amd64-k8-smp-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-amd64-xeon", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-amd64-xeon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-amd64-xeon-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-k7", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-k7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-k7-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-k7-smp", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-k7-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-k7-smp-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-power3", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-power3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-power3-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-power3-smp", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-power3-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-power3-smp-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-power4", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-power4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-power4-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-power4-smp", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-power4-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-power4-smp-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-powerpc", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-powerpc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-powerpc-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-powerpc-smp", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-headers-2.6.8.1-4-powerpc-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-powerpc-smp-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6-386", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6-386-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6-386-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6-686", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6-686-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6-686-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6-686-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6-686-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6-686-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6-amd64-generic", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6-amd64-generic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6-amd64-generic-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6-amd64-k8", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6-amd64-k8-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6-amd64-k8-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6-amd64-k8-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6-amd64-k8-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6-amd64-k8-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6-amd64-xeon", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6-amd64-xeon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6-amd64-xeon-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6-k7", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6-k7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6-k7-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6-k7-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6-k7-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6-k7-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6-power3", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6-power3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6-power3-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6-power3-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6-power3-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6-power3-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6-power4", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6-power4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6-power4-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6-power4-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6-power4-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6-power4-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6-powerpc", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6-powerpc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6-powerpc-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6-powerpc-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6-powerpc-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6-powerpc-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-386", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-386-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-386-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-686", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-686-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-686-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-686-smp", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-686-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-686-smp-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-amd64-generic", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-amd64-generic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-amd64-generic-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-amd64-k8", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-amd64-k8-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-amd64-k8-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-amd64-k8-smp", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-amd64-k8-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-amd64-k8-smp-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-amd64-xeon", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-amd64-xeon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-amd64-xeon-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-k7", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-k7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-k7-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-k7-smp", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-k7-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-k7-smp-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-power3", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-power3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-power3-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-power3-smp", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-power3-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-power3-smp-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-power4", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-power4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-power4-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-power4-smp", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-power4-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-power4-smp-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-powerpc", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-powerpc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-powerpc-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-powerpc-smp", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-2.6.8.1-4-powerpc-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-powerpc-smp-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-386", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-386-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-386-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-686", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-686-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-686-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-686-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-686-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-686-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-amd64-generic", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-amd64-generic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-amd64-generic-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-amd64-k8", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-amd64-k8-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-amd64-k8-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-amd64-k8-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-amd64-k8-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-amd64-k8-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-amd64-xeon", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-amd64-xeon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-amd64-xeon-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-k7", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-k7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-k7-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-k7-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-k7-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-k7-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-power3", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-power3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-power3-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-power3-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-power3-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-power3-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-power4", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-power4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-power4-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-power4-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-power4-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-power4-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-powerpc", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-powerpc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-powerpc-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-powerpc-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-image-powerpc-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-powerpc-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-k7", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-k7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-k7-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-k7-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-k7-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-k7-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-patch-debian-2.6.8.1", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-patch-debian-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-patch-debian-2.6.8.1-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-power3", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-power3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-power3-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-power3-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-power3-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-power3-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-power4", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-power4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-power4-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-power4-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-power4-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-power4-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-powerpc", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-powerpc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-powerpc-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-powerpc-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-powerpc-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-powerpc-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-2.6-386", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-2.6-386-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-2.6-386-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-2.6-686", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-2.6-686-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-2.6-686-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-2.6-686-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-2.6-686-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-2.6-686-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-2.6-amd64-generic", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-2.6-amd64-generic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-2.6-amd64-generic-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-2.6-amd64-k8", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-2.6-amd64-k8-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-2.6-amd64-k8-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-2.6-amd64-k8-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-2.6-amd64-k8-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-2.6-amd64-k8-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-2.6-amd64-xeon", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-2.6-amd64-xeon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-2.6-amd64-xeon-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-2.6-k7", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-2.6-k7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-2.6-k7-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-2.6-k7-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-2.6-k7-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-2.6-k7-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-2.6-power3", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-2.6-power3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-2.6-power3-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-2.6-power3-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-2.6-power3-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-2.6-power3-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-2.6-power4", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-2.6-power4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-2.6-power4-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-2.6-power4-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-2.6-power4-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-2.6-power4-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-2.6-powerpc", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-2.6-powerpc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-2.6-powerpc-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-2.6-powerpc-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-2.6-powerpc-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-2.6-powerpc-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-2.6.8.1-4-386", pkgver: "2.6.8.1.3-5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-2.6.8.1-4-386-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-2.6.8.1-4-386-2.6.8.1.3-5
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-2.6.8.1-4-686", pkgver: "2.6.8.1.3-5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-2.6.8.1-4-686-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-2.6.8.1-4-686-2.6.8.1.3-5
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-2.6.8.1-4-686-smp", pkgver: "2.6.8.1.3-5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-2.6.8.1-4-686-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-2.6.8.1-4-686-smp-2.6.8.1.3-5
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-2.6.8.1-4-amd64-generic", pkgver: "2.6.8.1.3-5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-2.6.8.1-4-amd64-generic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-2.6.8.1-4-amd64-generic-2.6.8.1.3-5
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-2.6.8.1-4-amd64-k8", pkgver: "2.6.8.1.3-5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-2.6.8.1-4-amd64-k8-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-2.6.8.1-4-amd64-k8-2.6.8.1.3-5
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-2.6.8.1-4-amd64-k8-smp", pkgver: "2.6.8.1.3-5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-2.6.8.1-4-amd64-k8-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-2.6.8.1-4-amd64-k8-smp-2.6.8.1.3-5
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-2.6.8.1-4-amd64-xeon", pkgver: "2.6.8.1.3-5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-2.6.8.1-4-amd64-xeon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-2.6.8.1-4-amd64-xeon-2.6.8.1.3-5
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-2.6.8.1-4-k7", pkgver: "2.6.8.1.3-5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-2.6.8.1-4-k7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-2.6.8.1-4-k7-2.6.8.1.3-5
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-2.6.8.1-4-k7-smp", pkgver: "2.6.8.1.3-5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-2.6.8.1-4-k7-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-2.6.8.1-4-k7-smp-2.6.8.1.3-5
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-386", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-386-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-386-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-686", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-686-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-686-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-686-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-686-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-686-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-amd64-generic", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-amd64-generic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-amd64-generic-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-amd64-k8", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-amd64-k8-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-amd64-k8-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-amd64-k8-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-amd64-k8-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-amd64-k8-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-amd64-xeon", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-amd64-xeon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-amd64-xeon-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-k7", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-k7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-k7-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-k7-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-k7-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-k7-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-power3", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-power3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-power3-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-power3-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-power3-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-power3-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-power4", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-power4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-power4-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-power4-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-power4-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-power4-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-powerpc", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-powerpc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-powerpc-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-restricted-modules-powerpc-smp", pkgver: "2.6.8.1-14");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-restricted-modules-powerpc-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-restricted-modules-powerpc-smp-2.6.8.1-14
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-source-2.6.8.1", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-source-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-source-2.6.8.1-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-tree-2.6.8.1", pkgver: "2.6.8.1-16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package linux-tree-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-tree-2.6.8.1-2.6.8.1-16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "nvidia-glx", pkgver: "1.0.6111-1ubuntu8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package nvidia-glx-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to nvidia-glx-1.0.6111-1ubuntu8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "nvidia-glx-dev", pkgver: "1.0.6111-1ubuntu8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package nvidia-glx-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to nvidia-glx-dev-1.0.6111-1ubuntu8
');
}
found = ubuntu_check(osver: "4.10", pkgname: "nvidia-kernel-source", pkgver: "1.0.6111-1ubuntu8");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package nvidia-kernel-source-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to nvidia-kernel-source-1.0.6111-1ubuntu8
');
}

if (w) { security_hole(port: 0, data: desc); }
