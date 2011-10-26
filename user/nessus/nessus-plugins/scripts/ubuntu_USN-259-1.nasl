# This script was automatically generated from the 259-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "irssi-text" is missing a security patch.

Description :

A Denial of Service vulnerability was discoverd in irssi. The DCC
ACCEPT command handler did not sufficiently verify the remotely
specified arguments. A remote attacker could exploit this to crash
irssi by sending a specially crafted DCC commands.

Solution :

Upgrade to : 
- irssi-text-0.8.9+0.8.10rc5-0ubuntu4.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(21067);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "259-1");
script_summary(english:"irssi-text vulnerability");
script_name(english:"USN259-1 : irssi-text vulnerability");
script_cve_id("CVE-2006-0458");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "irssi-text", pkgver: "0.8.9+0.8.10rc5-0ubuntu4.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package irssi-text-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to irssi-text-0.8.9+0.8.10rc5-0ubuntu4.1
');
}

if (w) { security_hole(port: 0, data: desc); }
