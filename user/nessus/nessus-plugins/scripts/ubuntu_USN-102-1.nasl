# This script was automatically generated from the 102-1 Ubuntu Security Notice
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

Shaun Colley discovered a buffer overflow in "shar" that was triggered
by output files (specified with -o) with names longer than 49
characters. This could be exploited to run arbitrary attacker
specified code on systems that automatically process uploaded files
with shar.

Ulf Harnhammar discovered that shar does not check the data length
returned by the \'wc\' command. However, it is believed that this cannot
actually be exploited on real systems.

Solution :

Upgrade to : 
- sharutils-4.2.1-10ubuntu0.1 (Ubuntu 4.10)
- sharutils-doc-4.2.1-10ubuntu0.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20488);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "102-1");
script_summary(english:"sharutils vulnerabilities");
script_name(english:"USN102-1 : sharutils vulnerabilities");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "sharutils", pkgver: "4.2.1-10ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package sharutils-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to sharutils-4.2.1-10ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "sharutils-doc", pkgver: "4.2.1-10ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package sharutils-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to sharutils-doc-4.2.1-10ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
