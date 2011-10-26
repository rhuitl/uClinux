# This script was automatically generated from the 34-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- openssh-client 
- openssh-server 
- ssh 
- ssh-askpass-gnome 


Description :

@Mediaservice.net discovered two information leaks in the OpenSSH
server. When using password authentication, an attacker could
test whether a login name exists by measuring the time between
failed login attempts, i. e. the time after which the "password:"
prompt appears again.

A similar issue affects systems which do not allow root logins over
ssh ("PermitRootLogin no"). By measuring the time between login
attempts an attacker could check whether a given root password is
correct. This allowed determining weak root passwords using a brute
force attack.

Solution :

Upgrade to : 
- openssh-client-3.8.1p1-11ubuntu3.1 (Ubuntu 4.10)
- openssh-server-3.8.1p1-11ubuntu3.1 (Ubuntu 4.10)
- ssh-3.8.1p1-11ubuntu3.1 (Ubuntu 4.10)
- ssh-askpass-gnome-3.8.1p1-11ubuntu3.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20650);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "34-1");
script_summary(english:"openssh information leakage");
script_name(english:"USN34-1 : openssh information leakage");
script_cve_id("CVE-2003-0190");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "openssh-client", pkgver: "3.8.1p1-11ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openssh-client-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to openssh-client-3.8.1p1-11ubuntu3.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "openssh-server", pkgver: "3.8.1p1-11ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openssh-server-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to openssh-server-3.8.1p1-11ubuntu3.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "ssh", pkgver: "3.8.1p1-11ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package ssh-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to ssh-3.8.1p1-11ubuntu3.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "ssh-askpass-gnome", pkgver: "3.8.1p1-11ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package ssh-askpass-gnome-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to ssh-askpass-gnome-3.8.1p1-11ubuntu3.1
');
}

if (w) { security_hole(port: 0, data: desc); }
