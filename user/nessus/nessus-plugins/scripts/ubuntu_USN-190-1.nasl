# This script was automatically generated from the 190-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libsnmp-base 
- libsnmp-perl 
- libsnmp5 
- libsnmp5-dev 
- snmp 
- snmpd 
- tkmib 


Description :

A remote Denial of Service has been discovered in the SMNP (Simple
Network Management Protocol) library. If a SNMP agent uses TCP sockets
for communication, a malicious SNMP server could exploit this to crash
the agent. Please note that by default SNMP uses UDP sockets.

Solution :

Upgrade to : 
- libsnmp-base-5.1.2-6ubuntu2.1 (Ubuntu 5.04)
- libsnmp-perl-5.1.2-6ubuntu2.1 (Ubuntu 5.04)
- libsnmp5-5.1.2-6ubuntu2.1 (Ubuntu 5.04)
- libsnmp5-dev-5.1.2-6ubuntu2.1 (Ubuntu 5.04)
- snmp-5.1.2-6ubuntu2.1 (Ubuntu 5.04)
- snmpd-5.1.2-6ubuntu2.1 (Ubuntu 5.04)
- tkmib-5.1.2-6ubuntu2.1 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20603);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "190-1");
script_summary(english:"net-snmp vulnerability");
script_name(english:"USN190-1 : net-snmp vulnerability");
script_cve_id("CVE-2005-2177");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "libsnmp-base", pkgver: "5.1.2-6ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libsnmp-base-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libsnmp-base-5.1.2-6ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libsnmp-perl", pkgver: "5.1.2-6ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libsnmp-perl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libsnmp-perl-5.1.2-6ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libsnmp5", pkgver: "5.1.2-6ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libsnmp5-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libsnmp5-5.1.2-6ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libsnmp5-dev", pkgver: "5.1.2-6ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libsnmp5-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libsnmp5-dev-5.1.2-6ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "snmp", pkgver: "5.1.2-6ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package snmp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to snmp-5.1.2-6ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "snmpd", pkgver: "5.1.2-6ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package snmpd-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to snmpd-5.1.2-6ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "tkmib", pkgver: "5.1.2-6ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package tkmib-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to tkmib-5.1.2-6ubuntu2.1
');
}

if (w) { security_hole(port: 0, data: desc); }
