# This script was automatically generated from the 81-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- iptables 
- iptables-dev 


Description :

Faheem Mitha noticed that the "iptables" command did not always load
the required modules on its own as it was supposed to. This could lead
to firewall rules not being loaded on system startup.

Solution :

Upgrade to : 
- iptables-1.2.9-10ubuntu0.1 (Ubuntu 4.10)
- iptables-dev-1.2.9-10ubuntu0.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20705);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "81-1");
script_summary(english:"iptables vulnerability");
script_name(english:"USN81-1 : iptables vulnerability");
script_cve_id("CVE-2004-0986");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "iptables", pkgver: "1.2.9-10ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package iptables-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to iptables-1.2.9-10ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "iptables-dev", pkgver: "1.2.9-10ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package iptables-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to iptables-dev-1.2.9-10ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
