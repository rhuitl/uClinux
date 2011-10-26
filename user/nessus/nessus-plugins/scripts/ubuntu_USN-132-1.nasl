# This script was automatically generated from the 132-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- imagemagick 
- libmagick++6 
- libmagick++6-dev 
- libmagick6 
- libmagick6-dev 
- perlmagick 


Description :

Damian Put discovered a buffer overflow in the PNM image decoder.
Processing a specially crafted PNM file with a small "colors" value
resulted in a crash of the application that used the ImageMagick
library. (CVE-2005-1275)

Another Denial of Service vulnerability was found in the XWD decoder.
Specially crafted invalid color masks resulted in an infinite loop
which caused the application using the ImageMagick library to stop
working and use all available CPU resources.
(http://bugs.gentoo.org/show_bug.cgi?id=90423)

Solution :

Upgrade to : 
- imagemagick-6.0.6.2-2.1ubuntu1.1 (Ubuntu 5.04)
- libmagick++6-6.0.6.2-2.1ubuntu1.1 (Ubuntu 5.04)
- libmagick++6-dev-6.0.6.2-2.1ubuntu1.1 (Ubuntu 5.04)
- libmagick6-6.0.6.2-2.1ubuntu1.1 (Ubuntu 5.04)
- libmagick6-dev-6.0.6.2-2.1ubuntu1.1 (Ubuntu 5.04)
- perlmagick-6.0.6.2-2.1ubuntu1.1 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20523);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "132-1");
script_summary(english:"imagemagick vulnerabilities");
script_name(english:"USN132-1 : imagemagick vulnerabilities");
script_cve_id("CVE-2005-1275");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "imagemagick", pkgver: "6.0.6.2-2.1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package imagemagick-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to imagemagick-6.0.6.2-2.1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libmagick++6", pkgver: "6.0.6.2-2.1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libmagick++6-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libmagick++6-6.0.6.2-2.1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libmagick++6-dev", pkgver: "6.0.6.2-2.1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libmagick++6-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libmagick++6-dev-6.0.6.2-2.1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libmagick6", pkgver: "6.0.6.2-2.1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libmagick6-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libmagick6-6.0.6.2-2.1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libmagick6-dev", pkgver: "6.0.6.2-2.1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libmagick6-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libmagick6-dev-6.0.6.2-2.1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "perlmagick", pkgver: "6.0.6.2-2.1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package perlmagick-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to perlmagick-6.0.6.2-2.1ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
