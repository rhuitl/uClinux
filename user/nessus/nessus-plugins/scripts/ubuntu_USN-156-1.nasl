# This script was automatically generated from the 156-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libtiff-tools 
- libtiff4 
- libtiff4-dev 


Description :

Wouter Hanegraaff discovered that the TIFF library did not
sufficiently validate the "YCbCr subsampling" value in TIFF image
headers. Decoding a malicious image with a zero value resulted in an
arithmetic exception, which caused the program that uses the TIFF
library to crash. This leads to a Denial of Service in server
applications that use libtiff (like the CUPS printing system) and can
cause data loss in, for example, the Evolution email client.

Solution :

Upgrade to : 
- libtiff-tools-3.6.1-5ubuntu0.2 (Ubuntu 5.04)
- libtiff4-3.6.1-5ubuntu0.2 (Ubuntu 5.04)
- libtiff4-dev-3.6.1-5ubuntu0.2 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20559);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "156-1");
script_summary(english:"tiff vulnerability");
script_name(english:"USN156-1 : tiff vulnerability");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "libtiff-tools", pkgver: "3.6.1-5ubuntu0.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libtiff-tools-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libtiff-tools-3.6.1-5ubuntu0.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libtiff4", pkgver: "3.6.1-5ubuntu0.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libtiff4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libtiff4-3.6.1-5ubuntu0.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libtiff4-dev", pkgver: "3.6.1-5ubuntu0.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libtiff4-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libtiff4-dev-3.6.1-5ubuntu0.2
');
}

if (w) { security_hole(port: 0, data: desc); }
