# This script was automatically generated from the 243-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- tuxpaint 
- tuxpaint-data 


Description :

Javier Fernández-Sanguino Peña discovered that the tuxpaint-import.sh
script created a temporary file in an insecure way. This could allow a
symlink attack to create or overwrite arbitrary files with the
privileges of the user running tuxpaint.

Solution :

Upgrade to : 
- tuxpaint-0.9.14-2ubuntu0.1 (Ubuntu 5.10)
- tuxpaint-data-0.9.14-2ubuntu0.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(20790);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "243-1");
script_summary(english:"tuxpaint vulnerability");
script_name(english:"USN243-1 : tuxpaint vulnerability");
script_cve_id("CVE-2005-3340");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "tuxpaint", pkgver: "0.9.14-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package tuxpaint-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to tuxpaint-0.9.14-2ubuntu0.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "tuxpaint-data", pkgver: "0.9.14-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package tuxpaint-data-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to tuxpaint-data-0.9.14-2ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
