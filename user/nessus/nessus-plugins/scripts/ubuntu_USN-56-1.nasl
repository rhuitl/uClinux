# This script was automatically generated from the 56-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- exim4 
- exim4-base 
- exim4-config 
- exim4-daemon-heavy 
- exim4-daemon-light 
- eximon4 


Description :

A flaw has been found in the host_aton() function, which can overflow
a buffer if it is presented with an illegal IPv6 address that has more
than 8 components. When supplying certain command line parameters, the
input was not checked, so that a local attacker could possibly exploit
the buffer overflow to run arbitrary code with the privileges of the
Exim mail server. (CVE-2005-0021)

Additionally, the BASE64 decoder in the SPA authentication handler did
not check the size of its output buffer. By sending an invalid BASE64
authentication string, a remote attacker could overflow the buffer,
which could possibly be exploited to run arbitrary code with the
privileges of the Exim mail server. (CVE-2005-0022)

Solution :

Upgrade to : 
- exim4-4.34-5ubuntu1.1 (Ubuntu 4.10)
- exim4-base-4.34-5ubuntu1.1 (Ubuntu 4.10)
- exim4-config-4.34-5ubuntu1.1 (Ubuntu 4.10)
- exim4-daemon-heavy-4.34-5ubuntu1.1 (Ubuntu 4.10)
- exim4-daemon-light-4.34-5ubuntu1.1 (Ubuntu 4.10)
- eximon4-4.34-5ubuntu1.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20674);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "56-1");
script_summary(english:"exim4 vulnerabilities");
script_name(english:"USN56-1 : exim4 vulnerabilities");
script_cve_id("CVE-2005-0021","CVE-2005-0022");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "exim4", pkgver: "4.34-5ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package exim4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to exim4-4.34-5ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "exim4-base", pkgver: "4.34-5ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package exim4-base-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to exim4-base-4.34-5ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "exim4-config", pkgver: "4.34-5ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package exim4-config-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to exim4-config-4.34-5ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "exim4-daemon-heavy", pkgver: "4.34-5ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package exim4-daemon-heavy-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to exim4-daemon-heavy-4.34-5ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "exim4-daemon-light", pkgver: "4.34-5ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package exim4-daemon-light-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to exim4-daemon-light-4.34-5ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "eximon4", pkgver: "4.34-5ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package eximon4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to eximon4-4.34-5ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
