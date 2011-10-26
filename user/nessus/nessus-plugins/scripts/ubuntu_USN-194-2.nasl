# This script was automatically generated from the 194-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- info 
- texinfo 


Description :

USN-194-1 fixed a vulnerability in the \'texindex\' program.
Unfortunately this update introduced a regression that caused the
program to abort when cleaning up temporary files (which are used with
extraordinarily large input files). The updated packages fix this.

Solution :

Upgrade to : 
- info-4.7-2.2ubuntu2.1 (Ubuntu 5.10)
- texinfo-4.7-2.2ubuntu2.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(20761);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "194-2");
script_summary(english:"texinfo regression bug fix");
script_name(english:"USN194-2 : texinfo regression bug fix");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "info", pkgver: "4.7-2.2ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package info-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to info-4.7-2.2ubuntu2.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "texinfo", pkgver: "4.7-2.2ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package texinfo-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to texinfo-4.7-2.2ubuntu2.1
');
}

if (w) { security_hole(port: 0, data: desc); }
