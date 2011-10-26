# This script was automatically generated from the 12-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- ppp 
- ppp-dev 


Description :

It has been discovered that ppp does not properly verify certain data
structures used in the CBCP protocol. This vulnerability could allow
an attacker to cause the pppd server to crash due to an invalid memory
access, leading to a denial of service. However, there is no
possibility of code execution or privilege escalation.

Solution :

Upgrade to : 
- ppp-2.4.2+20040428-2ubuntu6.2 (Ubuntu 4.10)
- ppp-dev-2.4.2+20040428-2ubuntu6.2 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20508);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "12-1");
script_summary(english:"ppp Denial of Service");
script_name(english:"USN12-1 : ppp Denial of Service");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "ppp", pkgver: "2.4.2+20040428-2ubuntu6.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package ppp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to ppp-2.4.2+20040428-2ubuntu6.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "ppp-dev", pkgver: "2.4.2+20040428-2ubuntu6.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package ppp-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to ppp-dev-2.4.2+20040428-2ubuntu6.2
');
}

if (w) { security_hole(port: 0, data: desc); }
