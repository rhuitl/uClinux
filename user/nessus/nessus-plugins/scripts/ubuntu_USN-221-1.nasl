# This script was automatically generated from the 221-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- ipsec-tools 
- racoon 


Description :

The Oulu University Secure Programming Group discovered a remote
Denial of Service vulnerability in the racoon daemon. When the daemon
is configured to use aggressive mode, then it did not check whether
the peer sent all required payloads during the IKE negotiation phase.
A malicious IPsec peer could exploit this to crash the racoon daemon.

Please be aware that racoon is not officially supported by Ubuntu, the
package is in the \'universe\' component of the archive.

Solution :

Upgrade to : 
- ipsec-tools-0.6-1ubuntu1.1 (Ubuntu 5.10)
- racoon-0.6-1ubuntu1.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(20763);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "221-1");
script_summary(english:"ipsec-tools vulnerability");
script_name(english:"USN221-1 : ipsec-tools vulnerability");
script_cve_id("CVE-2005-3732");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "ipsec-tools", pkgver: "0.6-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package ipsec-tools-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to ipsec-tools-0.6-1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "racoon", pkgver: "0.6-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package racoon-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to racoon-0.6-1ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
