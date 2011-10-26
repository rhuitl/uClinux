# This script was automatically generated from the 209-1 Ubuntu Security Notice
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

An information disclosure vulnerability has been found in the SSH
server. When the GSSAPIAuthentication option was enabled, the SSH
server could send GSSAPI credentials even to users who attempted to
log in with a method other than GSSAPI. This could inadvertently
expose these credentials to an untrusted user.

Please note that this does not affect the default configuration of the
SSH server.

Solution :

Upgrade to : 
- openssh-client-3.9p1-1ubuntu2.1 (Ubuntu 5.04)
- openssh-server-3.9p1-1ubuntu2.1 (Ubuntu 5.04)
- ssh-3.9p1-1ubuntu2.1 (Ubuntu 5.04)
- ssh-askpass-gnome-3.9p1-1ubuntu2.1 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20626);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "209-1");
script_summary(english:"openssh vulnerability");
script_name(english:"USN209-1 : openssh vulnerability");
script_cve_id("CVE-2005-2798");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "openssh-client", pkgver: "3.9p1-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openssh-client-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openssh-client-3.9p1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "openssh-server", pkgver: "3.9p1-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package openssh-server-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to openssh-server-3.9p1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "ssh", pkgver: "3.9p1-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package ssh-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to ssh-3.9p1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "ssh-askpass-gnome", pkgver: "3.9p1-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package ssh-askpass-gnome-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to ssh-askpass-gnome-3.9p1-1ubuntu2.1
');
}

if (w) { security_hole(port: 0, data: desc); }
