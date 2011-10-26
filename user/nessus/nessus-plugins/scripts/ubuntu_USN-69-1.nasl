# This script was automatically generated from the 69-1 Ubuntu Security Notice
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

Max Vozeler discovered an integer overflow in camel-lock-helper. An
user-supplied length value was not validated, so that a value of -1
caused a buffer allocation of 0 bytes; this buffer was then filled by
an arbitrary amount of user-supplied data.

A local attacker or a malicious POP3 server could exploit this to
execute arbitrary code with root privileges (because camel-lock-helper
is installed as setuid root).

Solution :

Upgrade to : 
- evolution-2.0.2-0ubuntu2.1 (Ubuntu 4.10)
- evolution-dev-2.0.2-0ubuntu2.1 (Ubuntu 4.10)
- evolution1.5-2.0.2-0ubuntu2.1 (Ubuntu 4.10)
- evolution1.5-dev-2.0.2-0ubuntu2.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20689);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "69-1");
script_summary(english:"evolution vulnerability");
script_name(english:"USN69-1 : evolution vulnerability");
script_cve_id("CVE-2005-0102");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "evolution", pkgver: "2.0.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package evolution-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to evolution-2.0.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "evolution-dev", pkgver: "2.0.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package evolution-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to evolution-dev-2.0.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "evolution1.5", pkgver: "2.0.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package evolution1.5-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to evolution1.5-2.0.2-0ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "evolution1.5-dev", pkgver: "2.0.2-0ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package evolution1.5-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to evolution1.5-dev-2.0.2-0ubuntu2.1
');
}

if (w) { security_hole(port: 0, data: desc); }
