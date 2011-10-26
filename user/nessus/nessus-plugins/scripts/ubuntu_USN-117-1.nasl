# This script was automatically generated from the 117-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "cvs" is missing a security patch.

Description :

Alen Zukich discovered a buffer overflow in the processing of version
and author information in the CVS client. By tricking an user to
connect to a malicious CVS server, an attacker could exploit this to
execute arbitrary code with the privileges of the connecting user.

Solution :

Upgrade to : 
- cvs-1.12.9-9ubuntu0.1 (Ubuntu 4.10)
- cvs-1.12.9-9ubuntu0.1 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20505);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "117-1");
script_summary(english:"cvs vulnerability");
script_name(english:"USN117-1 : cvs vulnerability");
script_cve_id("CVE-2005-0753");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "cvs", pkgver: "1.12.9-9ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cvs-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cvs-1.12.9-9ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "cvs", pkgver: "1.12.9-9ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cvs-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to cvs-1.12.9-9ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
