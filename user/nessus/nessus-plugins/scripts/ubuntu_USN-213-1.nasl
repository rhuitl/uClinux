# This script was automatically generated from the 213-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "sudo" is missing a security patch.

Description :

Tavis Ormandy discovered a privilege escalation vulnerability in sudo.
On executing shell scripts with sudo, the "P4" and "SHELLOPTS"
environment variables were not cleaned properly. If sudo is set up to
grant limited sudo privileges to normal users this could be exploited
to run arbitrary commands as the target user.

Updated packags for Ubuntu 4.10:

Solution :

Upgrade to : 
- sudo-1.6.8p9-2ubuntu2.1 (Ubuntu 4.10)
- sudo-1.6.8p9-2ubuntu2.1 (Ubuntu 5.04)
- sudo-1.6.8p9-2ubuntu2.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(20631);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "213-1");
script_summary(english:"sudo vulnerability");
script_name(english:"USN213-1 : sudo vulnerability");
script_cve_id("CVE-2005-2959");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "sudo", pkgver: "1.6.8p9-2ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package sudo-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to sudo-1.6.8p9-2ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "sudo", pkgver: "1.6.8p9-2ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package sudo-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to sudo-1.6.8p9-2ubuntu2.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "sudo", pkgver: "1.6.8p9-2ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package sudo-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to sudo-1.6.8p9-2ubuntu2.1
');
}

if (w) { security_hole(port: 0, data: desc); }
