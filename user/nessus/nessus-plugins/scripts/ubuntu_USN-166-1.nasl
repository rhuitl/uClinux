# This script was automatically generated from the 166-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- evolution 
- evolution-dev 
- evolution1.5 
- evolution1.5-dev 


Description :

Ulf Harnhammar disovered several format string vulnerabilities in
Evolution. By tricking an user into viewing a specially crafted vCard
attached to an email, specially crafted contact data from an LDAP
server, specially crafted task lists from remote servers, or saving
Calendar entries with this malicious task list data, it was possible
for an attacker to execute arbitrary code with the privileges of the
user running Evolution.

In addition, this update fixes a Denial of Service vulnerability in
the mail attachment parser. This could be exploited to crash Evolution
by tricking an user into opening a malicious email with a specially
crafted attachment file name. This does only affect the Ubuntu 4.10
version, the Evolution package shipped with Ubuntu 5.04 is not
affected. (CVE-2005-0806)

Solution :

Upgrade to : 
- evolution-2.2.1.1-0ubuntu4.2 (Ubuntu 4.10)
- evolution-dev-2.2.1.1-0ubuntu4.2 (Ubuntu 4.10)
- evolution1.5-2.0.2-0ubuntu2.3 (Ubuntu 4.10)
- evolution1.5-dev-2.0.2-0ubuntu2.3 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20572);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "166-1");
script_summary(english:"evolution vulnerabilities");
script_name(english:"USN166-1 : evolution vulnerabilities");
script_cve_id("CVE-2005-0806");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "evolution", pkgver: "2.2.1.1-0ubuntu4.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package evolution-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to evolution-2.2.1.1-0ubuntu4.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "evolution-dev", pkgver: "2.2.1.1-0ubuntu4.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package evolution-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to evolution-dev-2.2.1.1-0ubuntu4.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "evolution1.5", pkgver: "2.0.2-0ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package evolution1.5-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to evolution1.5-2.0.2-0ubuntu2.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "evolution1.5-dev", pkgver: "2.0.2-0ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package evolution1.5-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to evolution1.5-dev-2.0.2-0ubuntu2.3
');
}

if (w) { security_hole(port: 0, data: desc); }
