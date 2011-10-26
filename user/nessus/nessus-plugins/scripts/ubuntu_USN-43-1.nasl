# This script was automatically generated from the 43-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- groff 
- groff-base 


Description :

Javier Fernández-Sanguino Peña discovered that the auxiliary scripts
"eqn2graph" and "pic2graph" created temporary files in an insecure
way, which allowed exploitation of a race condition to create or
overwrite files with the privileges of the user invoking the program.

Solution :

Upgrade to : 
- groff-1.18.1.1-1ubuntu0.2 (Ubuntu 4.10)
- groff-base-1.18.1.1-1ubuntu0.2 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20660);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "43-1");
script_summary(english:"groff vulnerabilities");
script_name(english:"USN43-1 : groff vulnerabilities");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "groff", pkgver: "1.18.1.1-1ubuntu0.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package groff-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to groff-1.18.1.1-1ubuntu0.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "groff-base", pkgver: "1.18.1.1-1ubuntu0.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package groff-base-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to groff-base-1.18.1.1-1ubuntu0.2
');
}

if (w) { security_hole(port: 0, data: desc); }
