# This script was automatically generated from the 104-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- sharutils 
- sharutils-doc 


Description :

Joey Hess discovered that "unshar" created temporary files in an
insecure manner. This could allow a symbolic link attack to create or
overwrite arbitrary files with the privileges of the user invoking the
program.

Solution :

Upgrade to : 
- sharutils-4.2.1-10ubuntu0.2 (Ubuntu 4.10)
- sharutils-doc-4.2.1-10ubuntu0.2 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20490);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "104-1");
script_summary(english:"sharutils vulnerability");
script_name(english:"USN104-1 : sharutils vulnerability");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "sharutils", pkgver: "4.2.1-10ubuntu0.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package sharutils-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to sharutils-4.2.1-10ubuntu0.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "sharutils-doc", pkgver: "4.2.1-10ubuntu0.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package sharutils-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to sharutils-doc-4.2.1-10ubuntu0.2
');
}

if (w) { security_hole(port: 0, data: desc); }
