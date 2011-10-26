# This script was automatically generated from the 172-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libsensors-dev 
- libsensors3 
- lm-sensors 
- sensord 


Description :

Javier Fernández-Sanguino Peña noticed that the pwmconfig script
created temporary files in an insecure manner. This could allow
a symlink attack to create or overwrite arbitrary files with full
root privileges since pwmconfig is usually executed by root.

Solution :

Upgrade to : 
- libsensors-dev-2.8.8-7ubuntu2.1 (Ubuntu 5.04)
- libsensors3-2.8.8-7ubuntu2.1 (Ubuntu 5.04)
- lm-sensors-2.8.8-7ubuntu2.1 (Ubuntu 5.04)
- sensord-2.8.8-7ubuntu2.1 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20579);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "172-1");
script_summary(english:"lm-sensors vulnerabilities");
script_name(english:"USN172-1 : lm-sensors vulnerabilities");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "libsensors-dev", pkgver: "2.8.8-7ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libsensors-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libsensors-dev-2.8.8-7ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libsensors3", pkgver: "2.8.8-7ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libsensors3-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libsensors3-2.8.8-7ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "lm-sensors", pkgver: "2.8.8-7ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package lm-sensors-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to lm-sensors-2.8.8-7ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "sensord", pkgver: "2.8.8-7ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package sensord-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to sensord-2.8.8-7ubuntu2.1
');
}

if (w) { security_hole(port: 0, data: desc); }
