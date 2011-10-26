# This script was automatically generated from the 248-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "unzip" is missing a security patch.

Description :

A buffer overflow was discovered in the handling of file name
arguments. By tricking a user or automated system into processing a
specially crafted, excessively long file name with unzip, an attacker
could exploit this to execute arbitrary code with the user\'s
privileges.

Solution :

Upgrade to : 
- unzip-5.52-3ubuntu2.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(21056);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "248-1");
script_summary(english:"unzip vulnerability");
script_name(english:"USN248-1 : unzip vulnerability");
script_cve_id("CVE-2005-4667");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "unzip", pkgver: "5.52-3ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package unzip-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to unzip-5.52-3ubuntu2.1
');
}

if (w) { security_hole(port: 0, data: desc); }
