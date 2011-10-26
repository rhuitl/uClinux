# This script was automatically generated from the 142-1 Ubuntu Security Notice
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

Charles Morris discovered a race condition in sudo which could lead to
privilege escalation. If /etc/sudoers allowed a user the execution of
selected programs, and this was followed by another line containing
the pseudo-command "ALL", that user could execute arbitrary commands
with sudo by creating symbolic links at a certain time.

Please note that this does not affect a standard Ubuntu installation.

Solution :

Upgrade to : 
- sudo-1.6.8p5-1ubuntu2.1 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20535);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "142-1");
script_summary(english:"sudo vulnerability");
script_name(english:"USN142-1 : sudo vulnerability");
script_cve_id("CVE-2005-1993");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "sudo", pkgver: "1.6.8p5-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package sudo-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to sudo-1.6.8p5-1ubuntu2.1
');
}

if (w) { security_hole(port: 0, data: desc); }
