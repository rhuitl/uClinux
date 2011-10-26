# This script was automatically generated from the 128-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "nasm" is missing a security patch.

Description :

Josh Bressers discovered a buffer overflow in the ieee_putascii()
function of nasm. If an attacker tricked a user into assembling a
malicious source file, they could exploit this to execute arbitrary
code with the privileges of the user that runs nasm.

Solution :

Upgrade to : 
- nasm-0.98.38-1ubuntu0.2 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20518);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "128-1");
script_summary(english:"nasm vulnerability");
script_name(english:"USN128-1 : nasm vulnerability");
script_cve_id("CVE-2005-1194");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "nasm", pkgver: "0.98.38-1ubuntu0.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package nasm-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to nasm-0.98.38-1ubuntu0.2
');
}

if (w) { security_hole(port: 0, data: desc); }
