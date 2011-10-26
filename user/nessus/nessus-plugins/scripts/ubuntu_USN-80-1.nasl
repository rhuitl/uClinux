# This script was automatically generated from the 80-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libapache2-mod-python 
- libapache2-mod-python-doc 
- libapache2-mod-python2.2 
- libapache2-mod-python2.3 


Description :

Graham Dumpleton discovered an information disclosure in the
"publisher" handle of mod_python. By requesting a carefully crafted
URL for a published module page, anybody can obtain extra information
about internal variables, objects, and other information which is not
intended to be visible.

Solution :

Upgrade to : 
- libapache2-mod-python-3.1.3-1ubuntu3.2 (Ubuntu 4.10)
- libapache2-mod-python-doc-3.1.3-1ubuntu3.2 (Ubuntu 4.10)
- libapache2-mod-python2.2-3.1.3-1ubuntu3.2 (Ubuntu 4.10)
- libapache2-mod-python2.3-3.1.3-1ubuntu3.2 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20704);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "80-1");
script_summary(english:"libapache2-mod-python vulnerabilities");
script_name(english:"USN80-1 : libapache2-mod-python vulnerabilities");
script_cve_id("CVE-2005-0088");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "libapache2-mod-python", pkgver: "3.1.3-1ubuntu3.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libapache2-mod-python-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libapache2-mod-python-3.1.3-1ubuntu3.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libapache2-mod-python-doc", pkgver: "3.1.3-1ubuntu3.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libapache2-mod-python-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libapache2-mod-python-doc-3.1.3-1ubuntu3.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libapache2-mod-python2.2", pkgver: "3.1.3-1ubuntu3.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libapache2-mod-python2.2-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libapache2-mod-python2.2-3.1.3-1ubuntu3.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libapache2-mod-python2.3", pkgver: "3.1.3-1ubuntu3.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libapache2-mod-python2.3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libapache2-mod-python2.3-3.1.3-1ubuntu3.2
');
}

if (w) { security_hole(port: 0, data: desc); }
