# This script was automatically generated from the 190-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libsnmp4.2 
- libsnmp4.2-dev 


Description :

USN-190-1 fixed a vulnerability in the net-snmp library. It was
discovered that the same problem also affects the ucs-snmp
implementation (which is used by the Cyrus email server).

Original advisory:

  A remote Denial of Service has been discovered in the SMNP (Simple
  Network Management Protocol) library. If a SNMP agent uses TCP sockets
  for communication, a malicious SNMP server could exploit this to crash
  the agent. Please note that by default SNMP uses UDP sockets.

Solution :

Upgrade to : 
- libsnmp4.2-4.2.5-5ubuntu0.1 (Ubuntu 5.10)
- libsnmp4.2-dev-4.2.5-5ubuntu0.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(20604);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "190-2");
script_summary(english:"ucd-snmp vulnerability");
script_name(english:"USN190-2 : ucd-snmp vulnerability");
script_cve_id("CVE-2005-2177");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "libsnmp4.2", pkgver: "4.2.5-5ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libsnmp4.2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libsnmp4.2-4.2.5-5ubuntu0.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libsnmp4.2-dev", pkgver: "4.2.5-5ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libsnmp4.2-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libsnmp4.2-dev-4.2.5-5ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
