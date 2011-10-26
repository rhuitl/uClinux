# This script was automatically generated from the 13-1 Ubuntu Security Notice
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

Recently, Trustix Secure Linux discovered a vulnerability in the groff
package. The utility "groffer" created a temporary directory in an
insecure way, which allowed exploitation of a race condition to create
or overwrite files with the privileges of the user invoking the
program.

Solution :

Upgrade to : 
- groff-1.18.1.1-1ubuntu0.1 (Ubuntu 4.10)
- groff-base-1.18.1.1-1ubuntu0.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20520);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "13-1");
script_summary(english:"groff utility vulnerability");
script_name(english:"USN13-1 : groff utility vulnerability");
script_cve_id("CVE-2004-0969");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "groff", pkgver: "1.18.1.1-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package groff-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to groff-1.18.1.1-1ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "groff-base", pkgver: "1.18.1.1-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package groff-base-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to groff-base-1.18.1.1-1ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
