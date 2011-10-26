# This script was automatically generated from the 265-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libcairo2 
- libcairo2-dev 
- libcairo2-doc 


Description :

When rendering glyphs, the cairo graphics rendering library did not
check the maximum length of character strings. A request to display
an excessively long string with cairo caused a program crash due to an
X library error.

Mike Davis discovered that this could be turned into a Denial of
Service attack in Evolution. An email with an attachment with very
long lines caused Evolution to crash repeatedly until that email was
manually removed from the mail folder.

This only affects Ubuntu 5.10. Previous Ubuntu releases did not use
libcairo for text rendering.

Solution :

Upgrade to : 
- libcairo2-1.0.2-0ubuntu1.1 (Ubuntu 5.10)
- libcairo2-dev-1.0.2-0ubuntu1.1 (Ubuntu 5.10)
- libcairo2-doc-1.0.2-0ubuntu1.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(21151);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "265-1");
script_summary(english:"libcairo vulnerability");
script_name(english:"USN265-1 : libcairo vulnerability");
script_cve_id("CVE-2006-0528");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "libcairo2", pkgver: "1.0.2-0ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcairo2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libcairo2-1.0.2-0ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libcairo2-dev", pkgver: "1.0.2-0ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcairo2-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libcairo2-dev-1.0.2-0ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libcairo2-doc", pkgver: "1.0.2-0ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcairo2-doc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libcairo2-doc-1.0.2-0ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
