# This script was automatically generated from the 173-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libpcre3 
- libpcre3-dev 
- pcregrep 
- pgrep 


Description :

A buffer overflow has been discovered in the PCRE, a widely used
library that provides Perl compatible regular expressions. Specially
crafted regular expressions triggered a buffer overflow. On systems
that accept arbitrary regular expressions from untrusted users, this
could be exploited to execute arbitrary code with the privileges of
the application using the library.

Solution :

Upgrade to : 
- libpcre3-4.5-1.1ubuntu0.5.04 (Ubuntu 5.04)
- libpcre3-dev-4.5-1.1ubuntu0.5.04 (Ubuntu 5.04)
- pcregrep-4.5-1.1ubuntu0.5.04 (Ubuntu 5.04)
- pgrep-4.5-1.1ubuntu0.5.04 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20580);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "173-1");
script_summary(english:"pcre3 vulnerability");
script_name(english:"USN173-1 : pcre3 vulnerability");
script_cve_id("CVE-2005-2491");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "libpcre3", pkgver: "4.5-1.1ubuntu0.5.04");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpcre3-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libpcre3-4.5-1.1ubuntu0.5.04
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libpcre3-dev", pkgver: "4.5-1.1ubuntu0.5.04");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libpcre3-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libpcre3-dev-4.5-1.1ubuntu0.5.04
');
}
found = ubuntu_check(osver: "5.04", pkgname: "pcregrep", pkgver: "4.5-1.1ubuntu0.5.04");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package pcregrep-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to pcregrep-4.5-1.1ubuntu0.5.04
');
}
found = ubuntu_check(osver: "5.04", pkgname: "pgrep", pkgver: "4.5-1.1ubuntu0.5.04");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package pgrep-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to pgrep-4.5-1.1ubuntu0.5.04
');
}

if (w) { security_hole(port: 0, data: desc); }
