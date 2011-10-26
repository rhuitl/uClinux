# This script was automatically generated from the 235-1 Ubuntu Security Notice
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

Charles Morris discovered a privilege escalation vulnerability in
sudo.  On executing Perl scripts with sudo, various environment
variables that affect Perl\'s library search path were not cleaned
properly. If sudo is set up to grant limited sudo execution of Perl
scripts to normal users, this could be exploited to run arbitrary
commands as the target user.

This security update also filters out environment variables that can
be exploited similarly with Python, Ruby, and zsh scripts.

Please note that this does not affect the default Ubuntu installation,
or any setup that just grants full root privileges to certain users.

Solution :

Upgrade to : 
- sudo-1.6.8p9-2ubuntu2.2 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(20779);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "235-1");
script_summary(english:"sudo vulnerability");
script_name(english:"USN235-1 : sudo vulnerability");
script_cve_id("CVE-2005-4158");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "sudo", pkgver: "1.6.8p9-2ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package sudo-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to sudo-1.6.8p9-2ubuntu2.2
');
}

if (w) { security_hole(port: 0, data: desc); }
