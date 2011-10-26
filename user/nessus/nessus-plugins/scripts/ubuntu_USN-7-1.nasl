# This script was automatically generated from the 7-1 Ubuntu Security Notice
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

A buffer overflow in imagemagick\'s EXIF parsing routine has been
discovered in imagemagick versions prior to 6.1.0. Trying to query
EXIF information of a malicious image file might result in execution
of arbitrary code with the user\'s privileges.

Since imagemagick can be used in custom printing systems, this also
might lead to privilege escalation (execute code with the printer
spooler\'s privileges). However, Ubuntu\'s standard printing system does
not use imagemagick, thus there is no risk of privilege escalation in
a standard installation.

Solution :

Upgrade to : 
- imagemagick-6.0.2.5-1ubuntu1.1 (Ubuntu 4.10)
- libmagick++6-6.0.2.5-1ubuntu1.1 (Ubuntu 4.10)
- libmagick++6-dev-6.0.2.5-1ubuntu1.1 (Ubuntu 4.10)
- libmagick6-6.0.2.5-1ubuntu1.1 (Ubuntu 4.10)
- libmagick6-dev-6.0.2.5-1ubuntu1.1 (Ubuntu 4.10)
- perlmagick-6.0.2.5-1ubuntu1.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20690);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "7-1");
script_summary(english:"imagemagick vulnerability");
script_name(english:"USN7-1 : imagemagick vulnerability");
script_cve_id("CVE-2004-0981");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "imagemagick", pkgver: "6.0.2.5-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package imagemagick-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to imagemagick-6.0.2.5-1ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libmagick++6", pkgver: "6.0.2.5-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libmagick++6-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libmagick++6-6.0.2.5-1ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libmagick++6-dev", pkgver: "6.0.2.5-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libmagick++6-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libmagick++6-dev-6.0.2.5-1ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libmagick6", pkgver: "6.0.2.5-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libmagick6-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libmagick6-6.0.2.5-1ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libmagick6-dev", pkgver: "6.0.2.5-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libmagick6-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libmagick6-dev-6.0.2.5-1ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "perlmagick", pkgver: "6.0.2.5-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package perlmagick-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to perlmagick-6.0.2.5-1ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
