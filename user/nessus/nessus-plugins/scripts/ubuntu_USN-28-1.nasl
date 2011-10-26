# This script was automatically generated from the 28-1 Ubuntu Security Notice
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

Liam Helmer discovered an input validation flaw in sudo. When the
standard shell "bash" starts up, it searches the environment for
variables with a value beginning with "()". For each of these
variables a function with the same name is created, with the function
body filled in from the environment variable\'s value.

A malicious user with sudo access to a shell script that uses bash can
use this feature to substitute arbitrary commands for any
non-fully-qualified programs called from the script. Therefore this
flaw can lead to privilege escalation.

Solution :

Upgrade to : 
- sudo-1.6.7p5-1ubuntu4.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20643);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "28-1");
script_summary(english:"sudo vulnerability");
script_name(english:"USN28-1 : sudo vulnerability");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "sudo", pkgver: "1.6.7p5-1ubuntu4.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package sudo-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to sudo-1.6.7p5-1ubuntu4.1
');
}

if (w) { security_hole(port: 0, data: desc); }
