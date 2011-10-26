# This script was automatically generated from the 151-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- zlib-bin 
- zlib1g 
- zlib1g-dev 


Description :

USN-148-1 fixed an improver input verification of zlib
(CVE-2005-2096). Markus Oberhumer discovered additional ways a
disrupted stream could trigger a buffer overflow and crash the
application using zlib, so another update is necessary.

zlib is used by hundreds of server and client applications, so this
vulnerability could be exploited to cause Denial of Service attacks to
almost all services provided by an Ubuntu system.

Solution :

Upgrade to : 
- zlib-bin-1.2.2-4ubuntu1.2 (Ubuntu 5.04)
- zlib1g-1.2.2-4ubuntu1.2 (Ubuntu 5.04)
- zlib1g-dev-1.2.2-4ubuntu1.2 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20549);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "151-1");
script_summary(english:"zlib vulnerability");
script_name(english:"USN151-1 : zlib vulnerability");
script_cve_id("CVE-2005-1849","CVE-2005-2096");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "zlib-bin", pkgver: "1.2.2-4ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package zlib-bin-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to zlib-bin-1.2.2-4ubuntu1.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "zlib1g", pkgver: "1.2.2-4ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package zlib1g-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to zlib1g-1.2.2-4ubuntu1.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "zlib1g-dev", pkgver: "1.2.2-4ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package zlib1g-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to zlib1g-dev-1.2.2-4ubuntu1.2
');
}

if (w) { security_hole(port: 0, data: desc); }
