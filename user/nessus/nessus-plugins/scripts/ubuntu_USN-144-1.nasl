# This script was automatically generated from the 144-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- dbus-1 
- dbus-1-dev 
- dbus-1-doc 
- dbus-1-utils 
- dbus-glib-1 
- dbus-glib-1-dev 
- python2.3-dbus 


Description :

Besides providing the global system-wide communication bus, dbus also
offers per-user "session" buses which applications in an user\'s
session can create and use to communicate with each other.  Daniel
Reed discovered that the default configuration of the session dbus
allowed a local user to connect to another user\'s session bus if its
address was known. The fixed packages restrict the default permissions
to the user who owns the session dbus instance.

Please note that a standard Ubuntu installation does not use the
session bus for anything, so this can only be exploited if you are
using custom software which uses it.

Solution :

Upgrade to : 
- dbus-1-0.22-1ubuntu2.1 (Ubuntu 4.10)
- dbus-1-dev-0.22-1ubuntu2.1 (Ubuntu 4.10)
- dbus-1-doc-0.22-1ubuntu2.1 (Ubuntu 4.10)
- dbus-1-utils-0.22-1ubuntu2.1 (Ubuntu 4.10)
- dbus-glib-1-0.22-1ubuntu2.1 (Ubuntu 4.10)
- dbus-glib-1-dev-0.22-1ubuntu2.1 (Ubuntu 4.10)
- python2.3-dbus-0.22-1ubuntu2.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20537);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "144-1");
script_summary(english:"dbus vulnerability");
script_name(english:"USN144-1 : dbus vulnerability");
script_cve_id("CVE-2005-0201");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "dbus-1", pkgver: "0.22-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package dbus-1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to dbus-1-0.22-1ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "dbus-1-dev", pkgver: "0.22-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package dbus-1-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to dbus-1-dev-0.22-1ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "dbus-1-doc", pkgver: "0.22-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package dbus-1-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to dbus-1-doc-0.22-1ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "dbus-1-utils", pkgver: "0.22-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package dbus-1-utils-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to dbus-1-utils-0.22-1ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "dbus-glib-1", pkgver: "0.22-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package dbus-glib-1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to dbus-glib-1-0.22-1ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "dbus-glib-1-dev", pkgver: "0.22-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package dbus-glib-1-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to dbus-glib-1-dev-0.22-1ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "python2.3-dbus", pkgver: "0.22-1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package python2.3-dbus-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to python2.3-dbus-0.22-1ubuntu2.1
');
}

if (w) { security_hole(port: 0, data: desc); }
