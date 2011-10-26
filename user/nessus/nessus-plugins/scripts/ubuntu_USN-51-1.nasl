# This script was automatically generated from the 51-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libkpathsea-dev 
- libkpathsea3 
- tetex-bin 


Description :

Javier Fernández-Sanguino Peña noticed that "xdvizilla", an auxiliary
script to integrate DVI file viewing in Mozilla-based browsers,
created temporary files and directories in an insecure manner. This
could allow a symbolic link attack to create or overwrite arbitrary
files with the privileges of the user invoking the program.

Solution :

Upgrade to : 
- libkpathsea-dev-2.0.2-21ubuntu0.4 (Ubuntu 4.10)
- libkpathsea3-2.0.2-21ubuntu0.4 (Ubuntu 4.10)
- tetex-bin-2.0.2-21ubuntu0.4 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20669);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "51-1");
script_summary(english:"tetex-bin vulnerability");
script_name(english:"USN51-1 : tetex-bin vulnerability");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "libkpathsea-dev", pkgver: "2.0.2-21ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libkpathsea-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libkpathsea-dev-2.0.2-21ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libkpathsea3", pkgver: "2.0.2-21ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libkpathsea3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libkpathsea3-2.0.2-21ubuntu0.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "tetex-bin", pkgver: "2.0.2-21ubuntu0.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package tetex-bin-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to tetex-bin-2.0.2-21ubuntu0.4
');
}

if (w) { security_hole(port: 0, data: desc); }
