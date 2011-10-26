# This script was automatically generated from the 76-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- emacs21 
- emacs21-bin-common 
- emacs21-common 
- emacs21-el 
- emacs21-nox 


Description :

Max Vozeler discovered a format string vulnerability in the "movemail"
utility of Emacs. By sending specially crafted packets, a malicious
POP3 server could cause a buffer overflow, which could have been
exploited to execute arbitrary code with the privileges of the user
and the "mail" group (since "movemail" is installed as "setgid mail").

Solution :

Upgrade to : 
- emacs21-21.3+1-5ubuntu4.2 (Ubuntu 4.10)
- emacs21-bin-common-21.3+1-5ubuntu4.2 (Ubuntu 4.10)
- emacs21-common-21.3+1-5ubuntu4.2 (Ubuntu 4.10)
- emacs21-el-21.3+1-5ubuntu4.2 (Ubuntu 4.10)
- emacs21-nox-21.3+1-5ubuntu4.2 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20698);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "76-1");
script_summary(english:"emacs21 vulnerability");
script_name(english:"USN76-1 : emacs21 vulnerability");
script_cve_id("CVE-2005-0100");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "emacs21", pkgver: "21.3+1-5ubuntu4.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package emacs21-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to emacs21-21.3+1-5ubuntu4.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "emacs21-bin-common", pkgver: "21.3+1-5ubuntu4.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package emacs21-bin-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to emacs21-bin-common-21.3+1-5ubuntu4.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "emacs21-common", pkgver: "21.3+1-5ubuntu4.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package emacs21-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to emacs21-common-21.3+1-5ubuntu4.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "emacs21-el", pkgver: "21.3+1-5ubuntu4.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package emacs21-el-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to emacs21-el-21.3+1-5ubuntu4.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "emacs21-nox", pkgver: "21.3+1-5ubuntu4.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package emacs21-nox-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to emacs21-nox-21.3+1-5ubuntu4.2
');
}

if (w) { security_hole(port: 0, data: desc); }
