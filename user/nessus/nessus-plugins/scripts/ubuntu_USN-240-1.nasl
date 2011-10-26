# This script was automatically generated from the 240-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- bogofilter 
- bogofilter-bdb 
- bogofilter-common 


Description :

A buffer overflow was found in bogofilter\'s character set conversion
handling. Certain invalid UTF-8 character sequences caused an invalid
memory access. By sending a specially crafted email, a remote attacker
could exploit this to crash bogofilter or possibly even execute
arbitrary code with bogofilter\'s privileges.

Solution :

Upgrade to : 
- bogofilter-0.95.2-1ubuntu1.1 (Ubuntu 5.10)
- bogofilter-bdb-0.95.2-1ubuntu1.1 (Ubuntu 5.10)
- bogofilter-common-0.95.2-1ubuntu1.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(20787);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "240-1");
script_summary(english:"bogofilter vulnerability");
script_name(english:"USN240-1 : bogofilter vulnerability");
script_cve_id("CVE-2005-4591");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "bogofilter", pkgver: "0.95.2-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package bogofilter-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to bogofilter-0.95.2-1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "bogofilter-bdb", pkgver: "0.95.2-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package bogofilter-bdb-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to bogofilter-bdb-0.95.2-1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "bogofilter-common", pkgver: "0.95.2-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package bogofilter-common-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to bogofilter-common-0.95.2-1ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
