# This script was automatically generated from the 10-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libxml2 
- libxml2-dev 
- libxml2-doc 
- libxml2-python2.3 
- libxml2-utils 


Description :

Several buffer overflows have been discovered in libxml2\'s FTP connection
and DNS resolution functions. Supplying very long FTP URLs or IP
addresses might result in execution of arbitrary code with the
privileges of the process using libxml2.

Since libxml2 is used in packages like php4-imagick, the vulnerability
also might lead to privilege escalation, like executing attacker
supplied code with a web server\'s privileges.

However, this does not affect the core XML parsing code, which is what
the majority of programs use this library for.

Solution :

Upgrade to : 
- libxml2-2.6.11-3ubuntu1.1 (Ubuntu 4.10)
- libxml2-dev-2.6.11-3ubuntu1.1 (Ubuntu 4.10)
- libxml2-doc-2.6.11-3ubuntu1.1 (Ubuntu 4.10)
- libxml2-python2.3-2.6.11-3ubuntu1.1 (Ubuntu 4.10)
- libxml2-utils-2.6.11-3ubuntu1.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20485);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "10-1");
script_summary(english:"XML library vulnerabilities");
script_name(english:"USN10-1 : XML library vulnerabilities");
script_cve_id("CVE-2004-0981");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "libxml2", pkgver: "2.6.11-3ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxml2-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxml2-2.6.11-3ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxml2-dev", pkgver: "2.6.11-3ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxml2-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxml2-dev-2.6.11-3ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxml2-doc", pkgver: "2.6.11-3ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxml2-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxml2-doc-2.6.11-3ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxml2-python2.3", pkgver: "2.6.11-3ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxml2-python2.3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxml2-python2.3-2.6.11-3ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxml2-utils", pkgver: "2.6.11-3ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libxml2-utils-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxml2-utils-2.6.11-3ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
