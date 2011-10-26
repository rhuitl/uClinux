# This script was automatically generated from the 89-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libxml-dev 
- libxml1 


Description :

Several buffer overflows have been discovered in libxml\'s FTP
connection and DNS resolution functions. Supplying very long FTP URLs
or IP addresses might result in execution of arbitrary code with the
privileges of the process using libxml.

This does not affect the core XML parsing code, which is what the
majority of programs use this library for.

Note: The same vulnerability was already fixed for libxml2 in
USN-10-1.

Solution :

Upgrade to : 
- libxml-dev-1.8.17-8ubuntu0.1 (Ubuntu 4.10)
- libxml1-1.8.17-8ubuntu0.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20714);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "89-1");
script_summary(english:"libxml vulnerabilities");
script_name(english:"USN89-1 : libxml vulnerabilities");
script_cve_id("CVE-2004-0989");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "libxml-dev", pkgver: "1.8.17-8ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxml-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxml-dev-1.8.17-8ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxml1", pkgver: "1.8.17-8ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxml1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxml1-1.8.17-8ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
