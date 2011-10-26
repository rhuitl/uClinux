# This script was automatically generated from the 168-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- gaim 
- gaim-data 
- gaim-dev 


Description :

Daniel Atallah discovered a Denial of Service vulnerability in the
file transfer handler of OSCAR (the module that handles various
instant messaging protocols like ICQ). A remote attacker could crash
the Gaim client of an user by attempting to send him a file with
a name that contains invalid UTF-8 characters. (CVE-2005-2102)

It was found that specially crafted "away" messages triggered a buffer
overflow. A remote attacker could exploit this to crash the Gaim
client or possibly even execute arbitrary code with the permissions of
the Gaim user. (CVE-2005-2103)

Szymon Zygmunt and Michał Bartoszkiewicz discovered a memory alignment
error in the Gadu library, which was fixed in USN-162-1. However, it
was discovered that Gaim contains a copy of the vulnerable code. By
sending specially crafted messages over the Gadu protocol, a remote
attacker could crash Gaim. (CVE-2005-2370)

Solution :

Upgrade to : 
- gaim-1.1.4-1ubuntu4.4 (Ubuntu 5.04)
- gaim-data-1.1.4-1ubuntu4.4 (Ubuntu 5.04)
- gaim-dev-1.1.4-1ubuntu4.4 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20574);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "168-1");
script_summary(english:"gaim vulnerabilities");
script_name(english:"USN168-1 : gaim vulnerabilities");
script_cve_id("CVE-2005-2102","CVE-2005-2103","CVE-2005-2370");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "gaim", pkgver: "1.1.4-1ubuntu4.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package gaim-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to gaim-1.1.4-1ubuntu4.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "gaim-data", pkgver: "1.1.4-1ubuntu4.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package gaim-data-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to gaim-data-1.1.4-1ubuntu4.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "gaim-dev", pkgver: "1.1.4-1ubuntu4.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package gaim-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to gaim-dev-1.1.4-1ubuntu4.4
');
}

if (w) { security_hole(port: 0, data: desc); }
