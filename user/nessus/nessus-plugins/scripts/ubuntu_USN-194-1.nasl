# This script was automatically generated from the 194-1 Ubuntu Security Notice
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

Frank Lichtenheld discovered that the "texindex" program created
temporary files in an insecure manner. This could allow a symlink
attack to create or overwrite arbitrary files with the privileges of
the user running texindex.

Solution :

Upgrade to : 
- info-4.7-2.2ubuntu1.1 (Ubuntu 5.04)
- texinfo-4.7-2.2ubuntu1.1 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20608);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "194-1");
script_summary(english:"texinfo vulnerability");
script_name(english:"USN194-1 : texinfo vulnerability");
script_cve_id("CVE-2005-3011");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "info", pkgver: "4.7-2.2ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package info-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to info-4.7-2.2ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "texinfo", pkgver: "4.7-2.2ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package texinfo-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to texinfo-4.7-2.2ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
