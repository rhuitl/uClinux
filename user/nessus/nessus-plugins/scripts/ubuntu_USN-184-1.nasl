# This script was automatically generated from the 184-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- bsdutils 
- mount 
- util-linux 
- util-linux-locales 


Description :

David Watson discovered that "umount -r" removed some restrictive
mount options like the "nosuid" flag. If /etc/fstab contains
user-mountable removable devices which specify the "nosuid" flag
(which is common practice for such devices), a local attacker could
exploit this to execute arbitrary programs with root privileges by
calling "umount -r" on a removable device.

This does not affect the default Ubuntu configuration. Since Ubuntu
mounts removable devices automatically, there is normally no need to
configure them manually in /etc/fstab.

Solution :

Upgrade to : 
- bsdutils-2.12p-2ubuntu2.2 (Ubuntu 5.04)
- mount-2.12p-2ubuntu2.2 (Ubuntu 5.04)
- util-linux-2.12p-2ubuntu2.2 (Ubuntu 5.04)
- util-linux-locales-2.12p-2ubuntu2.2 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20595);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "184-1");
script_summary(english:"util-linux vulnerability");
script_name(english:"USN184-1 : util-linux vulnerability");
script_cve_id("CVE-2005-2876");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "bsdutils", pkgver: "2.12p-2ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package bsdutils-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to bsdutils-2.12p-2ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mount", pkgver: "2.12p-2ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mount-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mount-2.12p-2ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "util-linux", pkgver: "2.12p-2ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package util-linux-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to util-linux-2.12p-2ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "util-linux-locales", pkgver: "2.12p-2ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package util-linux-locales-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to util-linux-locales-2.12p-2ubuntu2.2
');
}

if (w) { security_hole(port: 0, data: desc); }
