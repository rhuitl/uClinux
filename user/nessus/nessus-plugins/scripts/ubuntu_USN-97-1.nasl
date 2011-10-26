# This script was automatically generated from the 97-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- lbxproxy 
- libdps-dev 
- libdps1 
- libdps1-dbg 
- libice-dev 
- libice6 
- libice6-dbg 
- libsm-dev 
- libsm6 
- libsm6-dbg 
- libx11-6 
- libx11-6-dbg 
- libx11-dev 
- libxaw6 
- libxaw6-dbg 
- libxaw6-dev 
- libxaw7 
- libxaw7-dbg 
- libxaw7-dev 
- libxext-dev 
- libxext6 
- libxext6-dbg 
- libxft1 
- libxft1-dbg 
- libxi-dev 
- libxi6 
- libxi6-dbg 
- libxmu-dev 
- libxmu6 
- libxmu6-dbg 
- libxmuu-dev 
- libxmuu1 
- libxmuu1-dbg 
- libxp-dev 
- l
[...]

Description :

Chris Gilbert discovered a buffer overflow in the XPM library shipped
with XFree86. If an attacker tricked a user into loading a malicious
XPM image with an application that uses libxpm, he could exploit this
to execute arbitrary code with the privileges of the user opening the
image.

These overflows do not allow privilege escalation through the X
server; the overflows are in a client-side library.

Solution :

Upgrade to : 
- lbxproxy-4.3.0.dfsg.1-6ubuntu25.2 (Ubuntu 4.10)
- libdps-dev-4.3.0.dfsg.1-6ubuntu25.2 (Ubuntu 4.10)
- libdps1-4.3.0.dfsg.1-6ubuntu25.2 (Ubuntu 4.10)
- libdps1-dbg-4.3.0.dfsg.1-6ubuntu25.2 (Ubuntu 4.10)
- libice-dev-4.3.0.dfsg.1-6ubuntu25.2 (Ubuntu 4.10)
- libice6-4.3.0.dfsg.1-6ubuntu25.2 (Ubuntu 4.10)
- libice6-dbg-4.3.0.dfsg.1-6ubuntu25.2 (Ubuntu 4.10)
- libsm-dev-4.3.0.dfsg.1-6ubuntu25.2 (Ubuntu 4.10)
- libsm6-4.3.0.dfsg.1-6ubuntu25.2 (Ubuntu 4.10)
- libsm6-dbg-4.3.0.dfsg.1-6ubuntu25.2 (U
[...]


Risk factor : High
';

if (description) {
script_id(20723);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "97-1");
script_summary(english:"xfree86 vulnerability");
script_name(english:"USN97-1 : xfree86 vulnerability");
script_cve_id("CVE-2005-0605");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "lbxproxy", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package lbxproxy-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to lbxproxy-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libdps-dev", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libdps-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libdps-dev-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libdps1", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libdps1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libdps1-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libdps1-dbg", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libdps1-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libdps1-dbg-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libice-dev", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libice-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libice-dev-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libice6", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libice6-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libice6-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libice6-dbg", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libice6-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libice6-dbg-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libsm-dev", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libsm-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libsm-dev-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libsm6", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libsm6-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libsm6-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libsm6-dbg", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libsm6-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libsm6-dbg-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libx11-6", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libx11-6-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libx11-6-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libx11-6-dbg", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libx11-6-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libx11-6-dbg-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libx11-dev", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libx11-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libx11-dev-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxaw6", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxaw6-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxaw6-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxaw6-dbg", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxaw6-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxaw6-dbg-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxaw6-dev", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxaw6-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxaw6-dev-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxaw7", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxaw7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxaw7-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxaw7-dbg", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxaw7-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxaw7-dbg-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxaw7-dev", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxaw7-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxaw7-dev-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxext-dev", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxext-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxext-dev-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxext6", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxext6-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxext6-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxext6-dbg", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxext6-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxext6-dbg-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxft1", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxft1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxft1-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxft1-dbg", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxft1-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxft1-dbg-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxi-dev", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxi-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxi-dev-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxi6", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxi6-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxi6-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxi6-dbg", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxi6-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxi6-dbg-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxmu-dev", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxmu-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxmu-dev-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxmu6", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxmu6-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxmu6-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxmu6-dbg", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxmu6-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxmu6-dbg-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxmuu-dev", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxmuu-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxmuu-dev-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxmuu1", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxmuu1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxmuu1-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxmuu1-dbg", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxmuu1-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxmuu1-dbg-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxp-dev", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxp-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxp-dev-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxp6", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxp6-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxp6-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxp6-dbg", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxp6-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxp6-dbg-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxpm-dev", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxpm-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxpm-dev-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxpm4", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxpm4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxpm4-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxpm4-dbg", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxpm4-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxpm4-dbg-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxrandr-dev", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxrandr-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxrandr-dev-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxrandr2", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxrandr2-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxrandr2-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxrandr2-dbg", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxrandr2-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxrandr2-dbg-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxt-dev", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxt-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxt-dev-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxt6", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxt6-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxt6-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxt6-dbg", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxt6-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxt6-dbg-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxtrap-dev", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxtrap-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxtrap-dev-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxtrap6", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxtrap6-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxtrap6-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxtrap6-dbg", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxtrap6-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxtrap6-dbg-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxtst-dev", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxtst-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxtst-dev-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxtst6", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxtst6-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxtst6-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxtst6-dbg", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxtst6-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxtst6-dbg-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxv-dev", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxv-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxv-dev-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxv1", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxv1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxv1-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxv1-dbg", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxv1-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxv1-dbg-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "pm-dev", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package pm-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to pm-dev-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "proxymngr", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package proxymngr-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to proxymngr-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "twm", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package twm-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to twm-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "x-dev", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package x-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to x-dev-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "x-window-system", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package x-window-system-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to x-window-system-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "x-window-system-core", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package x-window-system-core-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to x-window-system-core-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "x-window-system-dev", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package x-window-system-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to x-window-system-dev-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xbase-clients", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xbase-clients-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xbase-clients-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xdm", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xdm-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xdm-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xfonts-100dpi", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xfonts-100dpi-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xfonts-100dpi-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xfonts-100dpi-transcoded", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xfonts-100dpi-transcoded-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xfonts-100dpi-transcoded-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xfonts-75dpi", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xfonts-75dpi-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xfonts-75dpi-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xfonts-75dpi-transcoded", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xfonts-75dpi-transcoded-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xfonts-75dpi-transcoded-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xfonts-base", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xfonts-base-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xfonts-base-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xfonts-base-transcoded", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xfonts-base-transcoded-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xfonts-base-transcoded-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xfonts-cyrillic", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xfonts-cyrillic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xfonts-cyrillic-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xfonts-scalable", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xfonts-scalable-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xfonts-scalable-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xfree86-common", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xfree86-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xfree86-common-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xfs", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xfs-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xfs-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xfwp", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xfwp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xfwp-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xlibmesa-dev", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xlibmesa-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xlibmesa-dev-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xlibmesa-dri", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xlibmesa-dri-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xlibmesa-dri-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xlibmesa-dri-dbg", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xlibmesa-dri-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xlibmesa-dri-dbg-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xlibmesa-gl", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xlibmesa-gl-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xlibmesa-gl-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xlibmesa-gl-dbg", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xlibmesa-gl-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xlibmesa-gl-dbg-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xlibmesa-gl-dev", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xlibmesa-gl-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xlibmesa-gl-dev-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xlibmesa-glu", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xlibmesa-glu-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xlibmesa-glu-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xlibmesa-glu-dbg", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xlibmesa-glu-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xlibmesa-glu-dbg-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xlibmesa-glu-dev", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xlibmesa-glu-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xlibmesa-glu-dev-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xlibmesa3", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xlibmesa3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xlibmesa3-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xlibmesa3-dbg", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xlibmesa3-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xlibmesa3-dbg-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xlibosmesa-dev", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xlibosmesa-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xlibosmesa-dev-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xlibosmesa4", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xlibosmesa4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xlibosmesa4-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xlibosmesa4-dbg", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xlibosmesa4-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xlibosmesa4-dbg-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xlibs", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xlibs-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xlibs-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xlibs-data", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xlibs-data-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xlibs-data-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xlibs-dbg", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xlibs-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xlibs-dbg-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xlibs-dev", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xlibs-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xlibs-dev-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xlibs-pic", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xlibs-pic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xlibs-pic-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xlibs-static-dev", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xlibs-static-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xlibs-static-dev-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xlibs-static-pic", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xlibs-static-pic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xlibs-static-pic-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xmh", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xmh-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xmh-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xnest", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xnest-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xnest-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xprt", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xprt-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xprt-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xserver-common", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xserver-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xserver-common-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xserver-xfree86", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xserver-xfree86-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xserver-xfree86-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xserver-xfree86-dbg", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xserver-xfree86-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xserver-xfree86-dbg-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xspecs", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xspecs-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xspecs-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xterm", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xterm-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xterm-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xutils", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xutils-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xutils-4.3.0.dfsg.1-6ubuntu25.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xvfb", pkgver: "4.3.0.dfsg.1-6ubuntu25.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xvfb-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xvfb-4.3.0.dfsg.1-6ubuntu25.2
');
}

if (w) { security_hole(port: 0, data: desc); }
