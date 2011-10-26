# This script was automatically generated from the 145-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "wget" is missing a security patch.

Description :

USN-145-1 fixed several vulnerabilities in wget. However, Ralph
Corderoy discovered some regressions that caused wget to crash in some
cases. The updated version fixes this flaw.

Solution :

Upgrade to : 
- wget-1.9.1-10ubuntu2.2 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20539);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "145-2");
script_summary(english:"wget bug fix");
script_name(english:"USN145-2 : wget bug fix");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "wget", pkgver: "1.9.1-10ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package wget-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to wget-1.9.1-10ubuntu2.2
');
}

if (w) { security_hole(port: 0, data: desc); }
