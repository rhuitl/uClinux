# This script was automatically generated from the 49-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "debmake" is missing a security patch.

Description :

Javier Fernández-Sanguino Peña noticed that the debstd script from
debmake, a deprecated helper package for Debian packaging, created
temporary directories in an insecure manner. This could allow a
symlink attack to create or overwrite arbitrary files with the
privileges of the user invoking the program.

Solution :

Upgrade to : 
- debmake-3.7.4ubuntu0.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20666);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "49-1");
script_summary(english:"debmake vulnerability");
script_name(english:"USN49-1 : debmake vulnerability");
script_cve_id("CVE-2004-1179");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "debmake", pkgver: "3.7.4ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package debmake-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to debmake-3.7.4ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
